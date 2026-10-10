"""`python -m gatekeeper.api` prints the OpenAPI schema.

The frontend's TypeScript types are generated from this output
(`npm run gen:api`), and CI checks the committed copy is current.
"""

import sys

from .app import schema_text

sys.stdout.write(schema_text())
