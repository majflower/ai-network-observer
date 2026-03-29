#!/bin/bash
# Import graph data from JSON to Neo4j - FIXED

LOGS_DIR="/home/maj/ai-network-observer/ai-network/logs"
LATEST_GRAPH=$(ls -t $LOGS_DIR/session_*_network_graph.json 2>/dev/null | head -1)

if [ -z "$LATEST_GRAPH" ]; then
    echo "No graph data found"
    exit 1
fi

echo "Importing from: $LATEST_GRAPH"

# Vérifier que le fichier est valide
if ! jq empty "$LATEST_GRAPH" 2>/dev/null; then
    echo "Invalid JSON file"
    exit 1
fi

# Compter nodes et links
NODE_COUNT=$(cat "$LATEST_GRAPH" | jq '.nodes | length')
LINK_COUNT=$(cat "$LATEST_GRAPH" | jq '.links | length')

echo "Found: $NODE_COUNT nodes, $LINK_COUNT links"

if [ "$NODE_COUNT" -eq 0 ]; then
    echo "Graph is empty, nothing to import"
    exit 0
fi

# Clear existing data
echo "Clearing existing data..."
docker exec network-graph-db cypher-shell -u neo4j -p networksecurity \
  "MATCH (n) DETACH DELETE n;" 2>/dev/null || true

# Extract and import nodes
echo "Importing nodes..."
cat "$LATEST_GRAPH" | jq -r '
.nodes[] |
"MERGE (n {id: \"\(.id)\"})
 SET n:\(if .type then .type else "Unknown" end),
     n.label = \"\(if .label then .label else .id end)\";"
' > /tmp/import_nodes.cypher

docker exec -i network-graph-db cypher-shell -u neo4j -p networksecurity < /tmp/import_nodes.cypher

# Extract and import edges (only if links exist)
if [ "$LINK_COUNT" -gt 0 ]; then
    echo "Importing edges..."
    cat "$LATEST_GRAPH" | jq -r '
    .links[] |
    "MATCH (a {id: \"\(.source)\"}), (b {id: \"\(.target)\"})
     MERGE (a)-[r:CONNECTED]->(b)
     SET r.type = \"\(if .type then .type else "generic" end)\";"
    ' > /tmp/import_edges.cypher
    
    docker exec -i network-graph-db cypher-shell -u neo4j -p networksecurity < /tmp/import_edges.cypher
fi

echo "✓ Import completed: $NODE_COUNT nodes, $LINK_COUNT edges"

# Verify
IMPORTED=$(docker exec network-graph-db cypher-shell -u neo4j -p networksecurity \
  "MATCH (n) RETURN count(n) as count;" --format plain | tail -1)

echo "Verification: $IMPORTED nodes in database"
