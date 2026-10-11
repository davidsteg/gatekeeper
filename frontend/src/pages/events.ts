// One line of text per audit record, for the Overview feed. Plain text
// only: an audit record holds agent-supplied values and is rendered as
// text nodes, never as markup.
const ADMIN_VERBS: Record<string, string> = {
  tool_create: "created tool",
  tool_update: "updated tool",
  tool_delete: "deleted tool",
  tool_enable: "enabled tool",
  tool_disable: "disabled tool",
  identity_create: "created identity",
  identity_update: "updated identity",
  identity_delete: "deleted identity",
  token_rotate: "rotated the API token of",
  password_set: "set the console password of",
  credential_create: "created credential",
  credential_rotate: "rotated credential",
  credential_delete: "deleted credential",
  pending_reject: "rejected request",
  pending_approve: "approved request",
  toolkit_propose: "proposed toolkit",
  toolkit_update_propose: "proposed a change to toolkit",
  toolkit_delete_propose: "proposed deleting toolkit",
  credential_bind_propose: "proposed a credential binding for toolkit",
  toolkit_deploy: "deployed toolkit",
  toolkit_update_deploy: "deployed a change to toolkit",
  toolkit_delete_deploy: "deleted toolkit",
  credential_bind_deploy: "deployed a credential binding for toolkit",
  toolkit_reject: "rejected the proposal for toolkit",
};

const s = (v: unknown) => (v === undefined || v === null ? "" : String(v));

export function describeEvent(record: Record<string, unknown>): { text: string; dot: string } {
  switch (record.kind) {
    case "call": {
      const reason = record.denial_reason ? ` (${s(record.denial_reason)})` : "";
      const dot = record.outcome === "ok" ? "bg-ok" : record.outcome === "unknown" ? "bg-warn" : "bg-deny";
      return { text: `${s(record.identity)} → ${s(record.tool)}${reason}`, dot };
    }
    case "admin_change": {
      // A proposal's target is a random ID; what was proposed reads better.
      if (record.action === "pending_propose") {
        return { text: `${s(record.actor)} proposed ${s(record.proposed_action)}`, dot: "bg-warn" };
      }
      const verb = ADMIN_VERBS[s(record.action)] ?? s(record.action);
      return { text: `${s(record.actor)} ${verb} ${s(record.target)}`, dot: "bg-primary" };
    }
    case "auth_failure":
      return { text: `Sign-in failed (${s(record.reason)})`, dot: "bg-deny" };
    case "ui_login":
      return { text: `${s(record.identity)} signed in`, dot: "bg-ok" };
    default:
      return { text: s(record.kind) || "event", dot: "bg-muted-foreground" };
  }
}
