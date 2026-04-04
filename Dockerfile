FROM node:22-slim

WORKDIR /app

# Install agent-audit from npm
RUN npm install -g @piiiico/agent-audit@0.3.0

# MCP server communicates over stdio
CMD ["agent-audit-mcp"]
