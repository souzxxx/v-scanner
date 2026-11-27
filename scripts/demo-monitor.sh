#!/usr/bin/env bash
set -euo pipefail

for tool in go jq; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Ferramenta necessária não encontrada: $tool" >&2
        exit 1
    fi
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SECONDS=0
DEMO_DIR="$(mktemp -d)"
trap 'rm -rf "$DEMO_DIR"' EXIT

BINARY="$DEMO_DIR/angela.exe"
TARGET="$DEMO_DIR/requirements.txt"
STATE="$DEMO_DIR/state.json"

echo "Compilando o Angela..."
CGO_ENABLED=0 go build -o "$BINARY" ./cmd/angela

run_round() {
    RESULT="$(
        "$BINARY" monitor \
            --file "$TARGET" \
            --state "$STATE" \
            --log= \
            --once \
            --json
    )"

    jq -e '
        (.error // "") == "" and
        (.new | type == "array") and
        (.resolved | type == "array")
    ' <<< "$RESULT" >/dev/null

    jq '{
        baseline,
        total_vulnerabilities,
        new: (.new | length),
        resolved: (.resolved | length),
        still_affected: (.still_affected | length)
    }' <<< "$RESULT"

    jq -r '
        if .baseline then
            "Baseline registrada; os itens existentes nao sao alertas novos."
        else
            (.new[] |
                "NOVA: \(.package) \(.version) \(.vulnerability.id)"),
            (.resolved[] |
                "RESOLVIDA: \(.package) \(.version) \(.vulnerability.id)")
        end
    ' <<< "$RESULT"
}

expect() {
    if ! jq -e "$1" <<< "$RESULT" >/dev/null; then
        echo "Resultado inesperado nesta etapa." >&2
        exit 1
    fi
}

echo
echo "1. Baseline: Django e Requests com versões antigas."
cp testdata/monitor/requirements-v1.txt "$TARGET"
run_round
expect '.baseline == true and (.new | length) > 0'

echo
echo "2. Mesma versão: nenhum alerta deve se repetir."
run_round
expect '
    .baseline == false and
    (.new | length) == 0 and
    (.resolved | length) == 0 and
    (.still_affected | length) == 0
'

echo
echo "3. Adicionamos Jinja2 vulnerável: só ele deve gerar alertas novos."
cp testdata/monitor/requirements-v2.txt "$TARGET"
run_round
expect '
    .baseline == false and
    (.new | length) > 0 and
    all(.new[]; .package == "jinja2") and
    (.resolved | length) == 0 and
    (.still_affected | length) == 0
'

echo
echo "4. Atualizamos Django: seus avisos antigos devem ser resolvidos."
cp testdata/monitor/requirements-v3.txt "$TARGET"
run_round
expect '
    .baseline == false and
    (.new | length) == 0 and
    (.resolved | length) > 0 and
    all(.resolved[]; .package == "django") and
    (.still_affected | length) == 0
'

echo
echo "5. Reinício: um novo processo recupera o estado sem repetir alertas."
run_round
expect '
    .baseline == false and
    (.new | length) == 0 and
    (.resolved | length) == 0 and
    (.still_affected | length) == 0
'

echo
echo "6. Simulação de uma CVE nova para uma versão que não mudou."
echo "Removemos um aviso do estado LOCAL para simular que era desconhecido."
echo "O OSV real não é alterado."

KEY="$(jq -er '.known | keys | first' "$STATE")"
echo "Aviso escolhido: $KEY"

jq --arg key "$KEY" 'del(.known[$key])' \
    "$STATE" > "$DEMO_DIR/state-next.json"
mv "$DEMO_DIR/state-next.json" "$STATE"

run_round
expect '
    .baseline == false and
    (.new | length) == 1 and
    (.resolved | length) == 0 and
    (.still_affected | length) == 0
'

FOUND_KEY="$(
    jq -r '
        .new[0] |
        "\(.package)@\(.version)#\(.vulnerability.id)"
    ' <<< "$RESULT"
)"

if [[ "$FOUND_KEY" != "$KEY" ]]; then
    echo "O alerta novo não corresponde ao aviso removido." >&2
    exit 1
fi

echo
echo "Todas as etapas passaram em ${SECONDS}s."

if (( SECONDS >= 60 )); then
    echo "A demo ultrapassou o limite de menos de 1 minuto." >&2
    exit 1
fi