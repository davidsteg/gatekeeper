//! Per-version wire surfaces (`mcp_types.methods`).
//!
//! Two jobs, both keyed by `(method, protocol version)`:
//!
//! * [`validate_client_request`]: the version gate (a method absent from
//!   a version's surface is METHOD_NOT_FOUND) and the params shape check
//!   (a mismatch is INVALID_PARAMS), with pydantic's lax coercion rules.
//! * [`serialize_server_result`]: the outbound sieve. Each surface model
//!   ignores (drops) fields its version's schema does not define, keeps the
//!   model's field order, drops `null` model fields (`exclude_none`) and
//!   fails on a result missing a required field.
//!
//! Shapes are per schema era: every handshake version validates against
//! the 2025-11-25 schema, 2026-07-28 against its own.

use serde_json::{Map, Number, Value};

use super::types::{is_modern_version, parse_python_int, KNOWN_PROTOCOL_VERSIONS};

#[derive(Clone, Copy)]
pub(crate) enum Ty {
    Any,
    Str,
    Bool,
    Int,
    Float,
    /// A float constrained to `0 <= x <= 1` (`Annotations.priority`).
    Unit,
    /// `dict[str, Any]`.
    Dict,
    /// `dict[str, T]`.
    DictOf(&'static Ty),
    List(&'static Ty),
    Lit(&'static [&'static str]),
    Model(&'static Model),
    Union(&'static [Ty]),
    /// `str | int` (`RequestId`, `ProgressToken`).
    StrOrInt,
}

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Extra {
    Ignore,
    Allow,
}

pub(crate) struct Field {
    pub name: &'static str,
    pub ty: Ty,
    pub required: bool,
}

pub(crate) struct Model {
    pub fields: &'static [Field],
    pub extra: Extra,
}

const fn opt(name: &'static str, ty: Ty) -> Field {
    Field { name, ty, required: false }
}

const fn req(name: &'static str, ty: Ty) -> Field {
    Field { name, ty, required: true }
}

// -- Validation (lax mode) ------------------------------------------------------

fn is_number(v: &Value) -> Option<&Number> {
    match v {
        Value::Number(n) => Some(n),
        _ => None,
    }
}

fn lax_bool(v: &Value) -> Option<bool> {
    match v {
        Value::Bool(b) => Some(*b),
        Value::Number(n) => match n.as_f64() {
            Some(f) if f == 0.0 => Some(false),
            Some(f) if f == 1.0 => Some(true),
            _ => None,
        },
        Value::String(s) => match s.to_ascii_lowercase().as_str() {
            "0" | "off" | "f" | "false" | "n" | "no" => Some(false),
            "1" | "on" | "t" | "true" | "y" | "yes" => Some(true),
            _ => None,
        },
        _ => None,
    }
}

fn lax_int(v: &Value) -> Option<Value> {
    match v {
        Value::Bool(b) => Some(Value::from(*b as i64)),
        Value::Number(n) if n.is_i64() || n.is_u64() => Some(v.clone()),
        Value::Number(n) => {
            let f = n.as_f64()?;
            (f.is_finite() && f.fract() == 0.0).then(|| Value::from(f as i64))
        }
        Value::String(s) => parse_python_int(s).map(|i| Value::from(i as i64)),
        _ => None,
    }
}

fn lax_float(v: &Value) -> Option<f64> {
    match v {
        Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse::<f64>().ok(),
        _ => None,
    }
}

/// Validate `v` against `ty` and return its dump, or `None` when invalid.
pub(crate) fn dump(ty: &Ty, v: &Value) -> Option<Value> {
    match ty {
        Ty::Any => Some(v.clone()),
        Ty::Str => v.is_string().then(|| v.clone()),
        Ty::Bool => lax_bool(v).map(Value::Bool),
        Ty::Int => lax_int(v),
        Ty::Float => lax_float(v).and_then(Number::from_f64).map(Value::Number),
        Ty::Unit => lax_float(v).filter(|f| (0.0..=1.0).contains(f)).and_then(Number::from_f64).map(Value::Number),
        Ty::Dict => v.is_object().then(|| v.clone()),
        Ty::DictOf(inner) => {
            let m = v.as_object()?;
            let mut out = Map::new();
            for (k, item) in m {
                out.insert(k.clone(), dump(inner, item)?);
            }
            Some(Value::Object(out))
        }
        Ty::List(inner) => {
            let items = v.as_array()?;
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(dump(inner, item)?);
            }
            Some(Value::Array(out))
        }
        Ty::Lit(options) => match v {
            Value::String(s) if options.contains(&s.as_str()) => Some(v.clone()),
            _ => None,
        },
        Ty::Model(model) => dump_model(model, v),
        Ty::Union(members) => members.iter().find_map(|m| dump(m, v)),
        Ty::StrOrInt => match v {
            Value::String(_) => Some(v.clone()),
            _ if is_number(v).is_some() || v.is_boolean() => lax_int(v),
            _ => None,
        },
    }
}

fn dump_model(model: &Model, v: &Value) -> Option<Value> {
    let m = v.as_object()?;
    let mut out = Map::new();
    for field in model.fields {
        match m.get(field.name) {
            None if field.required => return None,
            None => {}
            Some(Value::Null) if !field.required || !matches!(field.ty, Ty::Any) => {
                if field.required {
                    return None;
                }
            }
            Some(value) => {
                let dumped = dump(&field.ty, value)?;
                if !dumped.is_null() {
                    out.insert(field.name.to_string(), dumped);
                }
            }
        }
    }
    if model.extra == Extra::Allow {
        for (k, value) in m {
            if !value.is_null() && !model.fields.iter().any(|f| f.name == k) {
                out.insert(k.clone(), value.clone());
            }
        }
    }
    Some(Value::Object(out))
}

// -- 2025-11-25 schema (every handshake version) ---------------------------------

static META_25: Model = Model { fields: &[opt("progressToken", Ty::StrOrInt)], extra: Extra::Allow };
static ICON: Model = Model {
    fields: &[
        opt("mimeType", Ty::Str),
        opt("sizes", Ty::List(&Ty::Str)),
        req("src", Ty::Str),
        opt("theme", Ty::Lit(&["light", "dark"])),
    ],
    extra: Extra::Ignore,
};
static IMPLEMENTATION: Model = Model {
    fields: &[
        opt("description", Ty::Str),
        opt("icons", Ty::List(&Ty::Model(&ICON))),
        req("name", Ty::Str),
        opt("title", Ty::Str),
        req("version", Ty::Str),
        opt("websiteUrl", Ty::Str),
    ],
    extra: Extra::Ignore,
};
static FORM_URL: Model = Model { fields: &[opt("form", Ty::Dict), opt("url", Ty::Dict)], extra: Extra::Ignore };
static ROOTS: Model = Model { fields: &[opt("listChanged", Ty::Bool)], extra: Extra::Ignore };
static SAMPLING: Model = Model { fields: &[opt("context", Ty::Dict), opt("tools", Ty::Dict)], extra: Extra::Ignore };
static ELICIT_CREATE: Model = Model { fields: &[opt("create", Ty::Dict)], extra: Extra::Ignore };
static SAMPLING_CREATE: Model = Model { fields: &[opt("createMessage", Ty::Dict)], extra: Extra::Ignore };
static TASK_REQUESTS: Model = Model {
    fields: &[opt("elicitation", Ty::Model(&ELICIT_CREATE)), opt("sampling", Ty::Model(&SAMPLING_CREATE))],
    extra: Extra::Ignore,
};
static CLIENT_TASKS: Model = Model {
    fields: &[opt("cancel", Ty::Dict), opt("list", Ty::Dict), opt("requests", Ty::Model(&TASK_REQUESTS))],
    extra: Extra::Ignore,
};
static CLIENT_CAPS_25: Model = Model {
    fields: &[
        opt("elicitation", Ty::Model(&FORM_URL)),
        opt("experimental", Ty::DictOf(&Ty::Dict)),
        opt("roots", Ty::Model(&ROOTS)),
        opt("sampling", Ty::Model(&SAMPLING)),
        opt("tasks", Ty::Model(&CLIENT_TASKS)),
    ],
    extra: Extra::Ignore,
};
const LOG_LEVELS: &[&str] = &["alert", "critical", "debug", "emergency", "error", "info", "notice", "warning"];

static P25_REQUEST: Model = Model { fields: &[opt("_meta", Ty::Model(&META_25))], extra: Extra::Ignore };
static P25_PAGINATED: Model =
    Model { fields: &[opt("_meta", Ty::Model(&META_25)), opt("cursor", Ty::Str)], extra: Extra::Ignore };
static P25_INITIALIZE: Model = Model {
    fields: &[
        opt("_meta", Ty::Model(&META_25)),
        req("capabilities", Ty::Model(&CLIENT_CAPS_25)),
        req("clientInfo", Ty::Model(&IMPLEMENTATION)),
        req("protocolVersion", Ty::Str),
    ],
    extra: Extra::Ignore,
};
static P25_SET_LEVEL: Model =
    Model { fields: &[opt("_meta", Ty::Model(&META_25)), req("level", Ty::Lit(LOG_LEVELS))], extra: Extra::Ignore };
static P25_GET_PROMPT: Model = Model {
    fields: &[opt("_meta", Ty::Model(&META_25)), opt("arguments", Ty::DictOf(&Ty::Str)), req("name", Ty::Str)],
    extra: Extra::Ignore,
};
static P25_URI: Model =
    Model { fields: &[opt("_meta", Ty::Model(&META_25)), req("uri", Ty::Str)], extra: Extra::Ignore };
static TASK_METADATA: Model = Model { fields: &[opt("ttl", Ty::Int)], extra: Extra::Ignore };
static P25_CALL_TOOL: Model = Model {
    fields: &[
        opt("_meta", Ty::Model(&META_25)),
        opt("arguments", Ty::Dict),
        req("name", Ty::Str),
        opt("task", Ty::Model(&TASK_METADATA)),
    ],
    extra: Extra::Ignore,
};
static ARGUMENT: Model = Model { fields: &[req("name", Ty::Str), req("value", Ty::Str)], extra: Extra::Ignore };
static COMPLETE_CONTEXT: Model = Model { fields: &[opt("arguments", Ty::DictOf(&Ty::Str))], extra: Extra::Ignore };
static PROMPT_REF: Model = Model {
    fields: &[req("name", Ty::Str), opt("title", Ty::Str), req("type", Ty::Lit(&["ref/prompt"]))],
    extra: Extra::Ignore,
};
static RESOURCE_TEMPLATE_REF: Model =
    Model { fields: &[req("type", Ty::Lit(&["ref/resource"])), req("uri", Ty::Str)], extra: Extra::Ignore };
const REF_UNION: Ty = Ty::Union(&[Ty::Model(&PROMPT_REF), Ty::Model(&RESOURCE_TEMPLATE_REF)]);
static P25_COMPLETE: Model = Model {
    fields: &[
        opt("_meta", Ty::Model(&META_25)),
        req("argument", Ty::Model(&ARGUMENT)),
        opt("context", Ty::Model(&COMPLETE_CONTEXT)),
        req("ref", REF_UNION),
    ],
    extra: Extra::Ignore,
};
static NOTIFICATION_PARAMS_25: Model = Model { fields: &[opt("_meta", Ty::Dict)], extra: Extra::Ignore };
static CANCELLED_PARAMS_25: Model = Model {
    fields: &[opt("_meta", Ty::Dict), opt("reason", Ty::Str), opt("requestId", Ty::StrOrInt)],
    extra: Extra::Ignore,
};
static PROGRESS_PARAMS_25: Model = Model {
    fields: &[
        opt("_meta", Ty::Dict),
        opt("message", Ty::Str),
        req("progress", Ty::Float),
        req("progressToken", Ty::StrOrInt),
        opt("total", Ty::Float),
    ],
    extra: Extra::Ignore,
};

// -- 2026-07-28 schema -----------------------------------------------------------------

static CLIENT_CAPS_26: Model = Model {
    fields: &[
        opt("elicitation", Ty::Model(&FORM_URL)),
        opt("experimental", Ty::DictOf(&Ty::Dict)),
        opt("extensions", Ty::DictOf(&Ty::Dict)),
        opt("roots", Ty::Dict),
        opt("sampling", Ty::Model(&SAMPLING)),
    ],
    extra: Extra::Ignore,
};
static REQUEST_META_26: Model = Model {
    fields: &[
        req("io.modelcontextprotocol/clientCapabilities", Ty::Model(&CLIENT_CAPS_26)),
        opt("io.modelcontextprotocol/clientInfo", Ty::Model(&IMPLEMENTATION)),
        opt("io.modelcontextprotocol/logLevel", Ty::Lit(LOG_LEVELS)),
        req("io.modelcontextprotocol/protocolVersion", Ty::Str),
        opt("progressToken", Ty::StrOrInt),
    ],
    extra: Extra::Allow,
};
const META_26: Ty = Ty::Model(&REQUEST_META_26);
static P26_REQUEST: Model = Model { fields: &[req("_meta", META_26)], extra: Extra::Ignore };
static P26_PAGINATED: Model = Model { fields: &[req("_meta", META_26), opt("cursor", Ty::Str)], extra: Extra::Ignore };
static P26_GET_PROMPT: Model = Model {
    fields: &[
        req("_meta", META_26),
        opt("arguments", Ty::DictOf(&Ty::Str)),
        opt("inputResponses", Ty::DictOf(&Ty::Dict)),
        req("name", Ty::Str),
        opt("requestState", Ty::Str),
    ],
    extra: Extra::Ignore,
};
static P26_READ: Model = Model {
    fields: &[
        req("_meta", META_26),
        opt("inputResponses", Ty::DictOf(&Ty::Dict)),
        opt("requestState", Ty::Str),
        req("uri", Ty::Str),
    ],
    extra: Extra::Ignore,
};
static P26_CALL_TOOL: Model = Model {
    fields: &[
        req("_meta", META_26),
        opt("arguments", Ty::Dict),
        opt("inputResponses", Ty::DictOf(&Ty::Dict)),
        req("name", Ty::Str),
        opt("requestState", Ty::Str),
    ],
    extra: Extra::Ignore,
};
static P26_COMPLETE: Model = Model {
    fields: &[
        req("_meta", META_26),
        req("argument", Ty::Model(&ARGUMENT)),
        opt("context", Ty::Model(&COMPLETE_CONTEXT)),
        req("ref", REF_UNION),
    ],
    extra: Extra::Ignore,
};
static SUBSCRIPTION_FILTER: Model = Model {
    fields: &[
        opt("promptsListChanged", Ty::Bool),
        opt("resourceSubscriptions", Ty::List(&Ty::Str)),
        opt("resourcesListChanged", Ty::Bool),
        opt("toolsListChanged", Ty::Bool),
    ],
    extra: Extra::Ignore,
};
static P26_LISTEN: Model = Model {
    fields: &[req("_meta", META_26), req("notifications", Ty::Model(&SUBSCRIPTION_FILTER))],
    extra: Extra::Ignore,
};
static NOTIFICATION_META_26: Model =
    Model { fields: &[opt("io.modelcontextprotocol/subscriptionId", Ty::StrOrInt)], extra: Extra::Allow };
static CANCELLED_PARAMS_26: Model = Model {
    fields: &[opt("_meta", Ty::Model(&NOTIFICATION_META_26)), opt("reason", Ty::Str), req("requestId", Ty::StrOrInt)],
    extra: Extra::Ignore,
};

/// `(params model, params required)` of a client request at a version, or
/// `None` when the version's surface lacks the method.
fn request_surface(method: &str, version: &str) -> Option<(&'static Model, bool)> {
    if is_modern_version(version) {
        return Some(match method {
            "completion/complete" => (&P26_COMPLETE, true),
            "prompts/get" => (&P26_GET_PROMPT, true),
            "prompts/list" | "resources/list" | "resources/templates/list" | "tools/list" => (&P26_PAGINATED, true),
            "resources/read" => (&P26_READ, true),
            "server/discover" => (&P26_REQUEST, true),
            "subscriptions/listen" => (&P26_LISTEN, true),
            "tools/call" => (&P26_CALL_TOOL, true),
            _ => return None,
        });
    }
    Some(match method {
        "completion/complete" => (&P25_COMPLETE, true),
        "initialize" => (&P25_INITIALIZE, true),
        "logging/setLevel" => (&P25_SET_LEVEL, true),
        "ping" => (&P25_REQUEST, false),
        "prompts/get" => (&P25_GET_PROMPT, true),
        "prompts/list" | "resources/list" | "resources/templates/list" | "tools/list" => (&P25_PAGINATED, false),
        "resources/read" | "resources/subscribe" | "resources/unsubscribe" => (&P25_URI, true),
        "tools/call" => (&P25_CALL_TOOL, true),
        _ => return None,
    })
}

/// `SPEC_CLIENT_METHODS`: spec request methods a client may send at any version.
pub const SPEC_CLIENT_METHODS: [&str; 15] = [
    "completion/complete",
    "initialize",
    "logging/setLevel",
    "ping",
    "prompts/get",
    "prompts/list",
    "resources/list",
    "resources/read",
    "resources/subscribe",
    "resources/templates/list",
    "resources/unsubscribe",
    "tools/call",
    "tools/list",
    "server/discover",
    "subscriptions/listen",
];

/// `SPEC_CLIENT_NOTIFICATION_METHODS`.
pub const SPEC_CLIENT_NOTIFICATION_METHODS: [&str; 4] = [
    "notifications/cancelled",
    "notifications/initialized",
    "notifications/progress",
    "notifications/roots/list_changed",
];

#[derive(Debug, PartialEq)]
pub(crate) enum SurfaceError {
    /// `(method, version)` is not on the surface (the version gate).
    NotOnSurface,
    /// The body fails the surface shape.
    Invalid,
}

fn check_params(model: &Model, required: bool, params: Option<&Map<String, Value>>) -> Result<(), SurfaceError> {
    match params {
        None if required => Err(SurfaceError::Invalid),
        None => Ok(()),
        Some(p) => {
            if dump_model(model, &Value::Object(p.clone())).is_some() {
                Ok(())
            } else {
                Err(SurfaceError::Invalid)
            }
        }
    }
}

pub(crate) fn validate_client_request(
    method: &str,
    version: &str,
    params: Option<&Map<String, Value>>,
) -> Result<(), SurfaceError> {
    debug_assert!(KNOWN_PROTOCOL_VERSIONS.contains(&version));
    let (model, required) = request_surface(method, version).ok_or(SurfaceError::NotOnSurface)?;
    check_params(model, required, params)
}

pub(crate) fn validate_client_notification(
    method: &str,
    version: &str,
    params: Option<&Map<String, Value>>,
) -> Result<(), SurfaceError> {
    let (model, required): (&Model, bool) = if is_modern_version(version) {
        match method {
            "notifications/cancelled" => (&CANCELLED_PARAMS_26, true),
            _ => return Err(SurfaceError::NotOnSurface),
        }
    } else {
        match method {
            "notifications/cancelled" => (&CANCELLED_PARAMS_25, true),
            "notifications/initialized" | "notifications/roots/list_changed" => (&NOTIFICATION_PARAMS_25, false),
            "notifications/progress" => (&PROGRESS_PARAMS_25, true),
            _ => return Err(SurfaceError::NotOnSurface),
        }
    };
    check_params(model, required, params)
}

// -- Result surfaces ------------------------------------------------------------------

static TOOL_ANNOTATIONS: Model = Model {
    fields: &[
        opt("destructiveHint", Ty::Bool),
        opt("idempotentHint", Ty::Bool),
        opt("openWorldHint", Ty::Bool),
        opt("readOnlyHint", Ty::Bool),
        opt("title", Ty::Str),
    ],
    extra: Extra::Ignore,
};
static TOOL_EXECUTION: Model =
    Model { fields: &[opt("taskSupport", Ty::Lit(&["forbidden", "optional", "required"]))], extra: Extra::Ignore };
static SCHEMA_25: Model = Model {
    fields: &[
        opt("$schema", Ty::Str),
        opt("properties", Ty::DictOf(&Ty::Dict)),
        opt("required", Ty::List(&Ty::Str)),
        req("type", Ty::Lit(&["object"])),
    ],
    extra: Extra::Allow,
};
static TOOL_25: Model = Model {
    fields: &[
        opt("_meta", Ty::Dict),
        opt("annotations", Ty::Model(&TOOL_ANNOTATIONS)),
        opt("description", Ty::Str),
        opt("execution", Ty::Model(&TOOL_EXECUTION)),
        opt("icons", Ty::List(&Ty::Model(&ICON))),
        req("inputSchema", Ty::Model(&SCHEMA_25)),
        req("name", Ty::Str),
        opt("outputSchema", Ty::Model(&SCHEMA_25)),
        opt("title", Ty::Str),
    ],
    extra: Extra::Ignore,
};
static LIST_TOOLS_25: Model = Model {
    fields: &[opt("_meta", Ty::Dict), opt("nextCursor", Ty::Str), req("tools", Ty::List(&Ty::Model(&TOOL_25)))],
    extra: Extra::Ignore,
};

static ANNOTATIONS: Model = Model {
    fields: &[
        opt("audience", Ty::List(&Ty::Lit(&["assistant", "user"]))),
        opt("lastModified", Ty::Str),
        opt("priority", Ty::Unit),
    ],
    extra: Extra::Ignore,
};

macro_rules! content_models {
    ($meta:expr, $text:ident, $image:ident, $audio:ident, $link:ident, $tres:ident, $bres:ident, $embedded:ident, $block:ident) => {
        static $text: Model = Model {
            fields: &[
                opt("_meta", $meta),
                opt("annotations", Ty::Model(&ANNOTATIONS)),
                req("text", Ty::Str),
                req("type", Ty::Lit(&["text"])),
            ],
            extra: Extra::Ignore,
        };
        static $image: Model = Model {
            fields: &[
                opt("_meta", $meta),
                opt("annotations", Ty::Model(&ANNOTATIONS)),
                req("data", Ty::Str),
                req("mimeType", Ty::Str),
                req("type", Ty::Lit(&["image"])),
            ],
            extra: Extra::Ignore,
        };
        static $audio: Model = Model {
            fields: &[
                opt("_meta", $meta),
                opt("annotations", Ty::Model(&ANNOTATIONS)),
                req("data", Ty::Str),
                req("mimeType", Ty::Str),
                req("type", Ty::Lit(&["audio"])),
            ],
            extra: Extra::Ignore,
        };
        static $link: Model = Model {
            fields: &[
                opt("_meta", $meta),
                opt("annotations", Ty::Model(&ANNOTATIONS)),
                opt("description", Ty::Str),
                opt("icons", Ty::List(&Ty::Model(&ICON))),
                opt("mimeType", Ty::Str),
                req("name", Ty::Str),
                opt("size", Ty::Int),
                opt("title", Ty::Str),
                req("type", Ty::Lit(&["resource_link"])),
                req("uri", Ty::Str),
            ],
            extra: Extra::Ignore,
        };
        static $tres: Model = Model {
            fields: &[opt("_meta", $meta), opt("mimeType", Ty::Str), req("text", Ty::Str), req("uri", Ty::Str)],
            extra: Extra::Ignore,
        };
        static $bres: Model = Model {
            fields: &[opt("_meta", $meta), req("blob", Ty::Str), opt("mimeType", Ty::Str), req("uri", Ty::Str)],
            extra: Extra::Ignore,
        };
        static $embedded: Model = Model {
            fields: &[
                opt("_meta", $meta),
                opt("annotations", Ty::Model(&ANNOTATIONS)),
                req("resource", Ty::Union(&[Ty::Model(&$tres), Ty::Model(&$bres)])),
                req("type", Ty::Lit(&["resource"])),
            ],
            extra: Extra::Ignore,
        };
        const $block: Ty = Ty::Union(&[
            Ty::Model(&$text),
            Ty::Model(&$image),
            Ty::Model(&$audio),
            Ty::Model(&$link),
            Ty::Model(&$embedded),
        ]);
    };
}

content_models!(Ty::Dict, TEXT_25, IMAGE_25, AUDIO_25, LINK_25, TRES_25, BRES_25, EMBEDDED_25, CONTENT_25);
static META_OBJECT: Model = Model { fields: &[], extra: Extra::Allow };
content_models!(
    Ty::Model(&META_OBJECT),
    TEXT_26,
    IMAGE_26,
    AUDIO_26,
    LINK_26,
    TRES_26,
    BRES_26,
    EMBEDDED_26,
    CONTENT_26
);

static CALL_TOOL_25: Model = Model {
    fields: &[
        opt("_meta", Ty::Dict),
        req("content", Ty::List(&CONTENT_25)),
        opt("isError", Ty::Bool),
        opt("structuredContent", Ty::Dict),
    ],
    extra: Extra::Ignore,
};
static PROMPTS_CAP: Model = Model { fields: &[opt("listChanged", Ty::Bool)], extra: Extra::Ignore };
static RESOURCES_CAP: Model =
    Model { fields: &[opt("listChanged", Ty::Bool), opt("subscribe", Ty::Bool)], extra: Extra::Ignore };
static TOOLS_CALL: Model = Model { fields: &[opt("call", Ty::Dict)], extra: Extra::Ignore };
static SERVER_TASK_REQUESTS: Model = Model { fields: &[opt("tools", Ty::Model(&TOOLS_CALL))], extra: Extra::Ignore };
static SERVER_TASKS: Model = Model {
    fields: &[opt("cancel", Ty::Dict), opt("list", Ty::Dict), opt("requests", Ty::Model(&SERVER_TASK_REQUESTS))],
    extra: Extra::Ignore,
};
static SERVER_CAPS_25: Model = Model {
    fields: &[
        opt("completions", Ty::Dict),
        opt("experimental", Ty::DictOf(&Ty::Dict)),
        opt("logging", Ty::Dict),
        opt("prompts", Ty::Model(&PROMPTS_CAP)),
        opt("resources", Ty::Model(&RESOURCES_CAP)),
        opt("tasks", Ty::Model(&SERVER_TASKS)),
        opt("tools", Ty::Model(&PROMPTS_CAP)),
    ],
    extra: Extra::Ignore,
};
static INITIALIZE_25: Model = Model {
    fields: &[
        opt("_meta", Ty::Dict),
        req("capabilities", Ty::Model(&SERVER_CAPS_25)),
        opt("instructions", Ty::Str),
        req("protocolVersion", Ty::Str),
        req("serverInfo", Ty::Model(&IMPLEMENTATION)),
    ],
    extra: Extra::Ignore,
};
static EMPTY_25: Model = Model { fields: &[], extra: Extra::Allow };

static RESULT_META_26: Model =
    Model { fields: &[opt("io.modelcontextprotocol/serverInfo", Ty::Any)], extra: Extra::Allow };
static SCHEMA_IN_26: Model =
    Model { fields: &[opt("$schema", Ty::Str), req("type", Ty::Lit(&["object"]))], extra: Extra::Allow };
static SCHEMA_OUT_26: Model = Model { fields: &[opt("$schema", Ty::Str)], extra: Extra::Allow };
static TOOL_26: Model = Model {
    fields: &[
        opt("_meta", Ty::Model(&META_OBJECT)),
        opt("annotations", Ty::Model(&TOOL_ANNOTATIONS)),
        opt("description", Ty::Str),
        opt("icons", Ty::List(&Ty::Model(&ICON))),
        req("inputSchema", Ty::Model(&SCHEMA_IN_26)),
        req("name", Ty::Str),
        opt("outputSchema", Ty::Model(&SCHEMA_OUT_26)),
        opt("title", Ty::Str),
    ],
    extra: Extra::Ignore,
};
const CACHE_SCOPE: Ty = Ty::Lit(&["private", "public"]);
static LIST_TOOLS_26: Model = Model {
    fields: &[
        opt("_meta", Ty::Model(&RESULT_META_26)),
        req("cacheScope", CACHE_SCOPE),
        opt("nextCursor", Ty::Str),
        req("resultType", Ty::Str),
        req("tools", Ty::List(&Ty::Model(&TOOL_26))),
        req("ttlMs", Ty::Int),
    ],
    extra: Extra::Ignore,
};
static CALL_TOOL_26: Model = Model {
    fields: &[
        opt("_meta", Ty::Model(&RESULT_META_26)),
        req("content", Ty::List(&CONTENT_26)),
        opt("isError", Ty::Bool),
        req("resultType", Ty::Str),
        opt("structuredContent", Ty::Any),
    ],
    extra: Extra::Ignore,
};
static SERVER_CAPS_26: Model = Model {
    fields: &[
        opt("completions", Ty::Dict),
        opt("experimental", Ty::DictOf(&Ty::Dict)),
        opt("extensions", Ty::DictOf(&Ty::Dict)),
        opt("logging", Ty::Dict),
        opt("prompts", Ty::Model(&PROMPTS_CAP)),
        opt("resources", Ty::Model(&RESOURCES_CAP)),
        opt("tools", Ty::Model(&PROMPTS_CAP)),
    ],
    extra: Extra::Ignore,
};
static DISCOVER_26: Model = Model {
    fields: &[
        opt("_meta", Ty::Model(&RESULT_META_26)),
        req("cacheScope", CACHE_SCOPE),
        req("capabilities", Ty::Model(&SERVER_CAPS_26)),
        opt("instructions", Ty::Str),
        req("resultType", Ty::Str),
        req("supportedVersions", Ty::List(&Ty::Str)),
        req("ttlMs", Ty::Int),
    ],
    extra: Extra::Ignore,
};
static LISTEN_META_26: Model = Model {
    fields: &[
        opt("io.modelcontextprotocol/serverInfo", Ty::Any),
        req("io.modelcontextprotocol/subscriptionId", Ty::StrOrInt),
    ],
    extra: Extra::Allow,
};
static LISTEN_26: Model = Model {
    fields: &[req("_meta", Ty::Model(&LISTEN_META_26)), req("resultType", Ty::Str)],
    extra: Extra::Ignore,
};

fn result_surface(method: &str, version: &str) -> Option<&'static Model> {
    if is_modern_version(version) {
        return match method {
            "tools/list" => Some(&LIST_TOOLS_26),
            "tools/call" => Some(&CALL_TOOL_26),
            "server/discover" => Some(&DISCOVER_26),
            "subscriptions/listen" => Some(&LISTEN_26),
            _ => None,
        };
    }
    match method {
        "initialize" => Some(&INITIALIZE_25),
        "ping" => Some(&EMPTY_25),
        "tools/list" => Some(&LIST_TOOLS_25),
        "tools/call" => Some(&CALL_TOOL_25),
        _ => None,
    }
}

/// Validate `data` against the version's result surface and return the
/// surface-shaped dump; `Err` means the handler returned an invalid
/// result. Methods without a surface row pass through unchanged.
pub(crate) fn serialize_server_result(method: &str, version: &str, data: &Value) -> Result<Value, ()> {
    match result_surface(method, version) {
        None => Ok(data.clone()),
        Some(model) => dump_model(model, data).ok_or(()),
    }
}

/// `SubscriptionFilter` parsed off a listen request (already validated).
pub(crate) fn subscription_filter(params: Option<&Map<String, Value>>) -> Value {
    params
        .and_then(|p| p.get("notifications"))
        .and_then(|n| dump_model(&SUBSCRIPTION_FILTER, n))
        .unwrap_or_else(|| Value::Object(Map::new()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn p(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn the_version_gate() {
        assert_eq!(validate_client_request("ping", "2026-07-28", None), Err(SurfaceError::NotOnSurface));
        assert_eq!(validate_client_request("server/discover", "2025-06-18", None), Err(SurfaceError::NotOnSurface));
        assert_eq!(validate_client_request("initialize", "2026-07-28", None), Err(SurfaceError::NotOnSurface));
        assert_eq!(validate_client_request("foo", "2025-06-18", None), Err(SurfaceError::NotOnSurface));
        assert_eq!(validate_client_request("ping", "2025-06-18", None), Ok(()));
    }

    #[test]
    fn params_shapes() {
        let v = "2025-06-18";
        assert_eq!(validate_client_request("tools/call", v, None), Err(SurfaceError::Invalid));
        assert_eq!(validate_client_request("tools/call", v, Some(&p(json!({"name": 5})))), Err(SurfaceError::Invalid));
        assert_eq!(
            validate_client_request("tools/call", v, Some(&p(json!({"name": "a", "arguments": [1]})))),
            Err(SurfaceError::Invalid)
        );
        assert_eq!(
            validate_client_request("tools/call", v, Some(&p(json!({"name": "a", "arguments": null})))),
            Ok(())
        );
        assert_eq!(
            validate_client_request("initialize", v, Some(&p(json!({"protocolVersion": "x", "capabilities": {}})))),
            Err(SurfaceError::Invalid)
        );
        assert_eq!(
            validate_client_request("logging/setLevel", v, Some(&p(json!({"level": "info"})))),
            Ok(())
        );
        assert_eq!(
            validate_client_request("ping", v, Some(&p(json!({"_meta": {"progressToken": [1]}})))),
            Err(SurfaceError::Invalid)
        );
        let meta = json!({"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                          "io.modelcontextprotocol/clientCapabilities": {}});
        assert_eq!(
            validate_client_request("subscriptions/listen", "2026-07-28", Some(&p(json!({"_meta": meta})))),
            Err(SurfaceError::Invalid)
        );
        assert_eq!(
            validate_client_request(
                "tools/list",
                "2026-07-28",
                Some(&p(json!({"_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                                           "io.modelcontextprotocol/clientCapabilities": {},
                                           "io.modelcontextprotocol/clientInfo": {"name": "x"}}})))
            ),
            Err(SurfaceError::Invalid)
        );
    }

    #[test]
    fn the_sieve_drops_what_a_version_does_not_define() {
        let data = json!({"tools": [{"name": "a", "inputSchema": {"type": "object", "properties": {"x": {"type": "string", "default": null}}, "foo": null},
                          "_meta": {"k": null}, "annotations": {"title": null, "readOnlyHint": true, "extra": 1},
                          "unknownField": 3, "execution": {"taskSupport": "optional"}}],
                          "ttlMs": 0, "cacheScope": "private", "resultType": "complete", "_meta": {"z": null}});
        assert_eq!(
            serialize_server_result("tools/list", "2025-06-18", &data).unwrap(),
            json!({"_meta": {"z": null}, "tools": [{"_meta": {"k": null}, "annotations": {"readOnlyHint": true},
                   "execution": {"taskSupport": "optional"},
                   "inputSchema": {"properties": {"x": {"type": "string", "default": null}}, "type": "object"}, "name": "a"}]})
        );
        let modern = serialize_server_result("tools/list", "2026-07-28", &data).unwrap();
        assert_eq!(
            modern,
            json!({"_meta": {}, "cacheScope": "private", "resultType": "complete",
                   "tools": [{"_meta": {}, "annotations": {"readOnlyHint": true},
                              "inputSchema": {"type": "object", "properties": {"x": {"type": "string", "default": null}}}, "name": "a"}],
                   "ttlMs": 0})
        );
        // Key order is the surface model's.
        let keys: Vec<&String> = modern["tools"][0]["inputSchema"].as_object().unwrap().keys().collect();
        assert_eq!(keys, ["type", "properties"]);
    }

    #[test]
    fn invalid_results_are_refused() {
        assert!(serialize_server_result("tools/call", "2025-06-18", &json!({"content": [{"type": "text"}]})).is_err());
        assert!(serialize_server_result("tools/list", "2025-06-18", &json!({"tools": [{"name": "x", "inputSchema": {"type": "array"}}]})).is_err());
        assert!(serialize_server_result("tools/call", "2025-06-18",
            &json!({"content": [{"type": "text", "text": "x", "annotations": {"priority": 2}}]})).is_err());
        assert_eq!(
            serialize_server_result("tools/call", "2025-06-18",
                &json!({"content": [{"type": "text", "text": "x", "annotations": {"priority": 1}}], "structuredContent": null})).unwrap(),
            json!({"content": [{"annotations": {"priority": 1.0}, "text": "x", "type": "text"}]})
        );
        assert_eq!(serialize_server_result("ping", "2025-06-18", &json!({"_meta": {"a": 1}, "x": 2})).unwrap(),
                   json!({"_meta": {"a": 1}, "x": 2}));
    }
}
