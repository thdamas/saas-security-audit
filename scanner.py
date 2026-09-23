"""
scanner.py — motor determinístico do saas-security-audit.

Zero LLM. Tudo aqui é contável, grepável e reproduzível: rodar duas vezes no mesmo código
dá o mesmo resultado. Ele NÃO julga. Ele inventaria, detecta o que é mecânico e PARTICIONA
o trabalho em lotes com lista explícita, provando por aritmética que a cobertura é 100%
sem sobreposição.

Por que existe: julgamento de LLM é caro e não reproduzível. Contar policy, achar
SECURITY DEFINER sem search_path e listar server function é barato e exato. Gastar agente
nisso é desperdício; pior, agente escolhendo o que auditar audita por amostragem sem
perceber.

Uso:
    python scanner.py --perfil <caminho/perfil.toml>              # escreve os artefatos
    python scanner.py --perfil <...> --print                      # também imprime o resumo
    python scanner.py --perfil <...> --modo leve --dimensao seguranca
    python scanner.py --perfil <...> --har <arquivo.har>          # soma a camada de execução
    python scanner.py --perfil <...> --saida <pasta>              # onde gravar (fora do repo!)
    python scanner.py --descobrir <raiz-do-app>                   # rascunho de perfil

Onde os artefatos são gravados, nesta ordem de precedência:
    1. --saida
    2. variável de ambiente SAAS_AUDIT_SAIDA
    3. ~/saas-security-audit/auditorias
Nunca dentro do repositório auditado: relatório de vulnerabilidade a um `git add .` do
GitHub errado é o próprio vazamento.

Garantias:
    - READ-ONLY sobre o app auditado. Nunca escreve, move ou apaga nada lá.
    - Nunca imprime nem grava valor de segredo: só o tipo e a localização.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    tomllib = None

# ---------------------------------------------------------------------------
# CONSTANTES AJUSTÁVEIS
# Se vier ruído, aperta; se vier pouco, afrouxa. Sempre testar com --print antes
# de confiar no número.
# ---------------------------------------------------------------------------

SAIDA_PADRAO = Path.home() / "saas-security-audit" / "auditorias"

# Tamanho dos lotes. Mexer aqui muda custo e granularidade da auditoria.
LOTE_TABELAS = 9
LOTE_SERVERFN = 17
LOTE_ROTAS_API = 7

# Headers de segurança que a config de deploy deveria trazer.
HEADERS_ESPERADOS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

# Padrões que PARECEM segredo hardcoded. Ruído alto de propósito: o agente confirma.
# NUNCA gravamos o valor casado, só arquivo, linha e o TIPO.
PADROES_SEGREDO = [
    ("chave Stripe live", re.compile(r"sk_live_[A-Za-z0-9]{8,}")),
    ("chave Stripe test", re.compile(r"sk_test_[A-Za-z0-9]{8,}")),
    ("JWT literal", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.")),
    ("chave Anthropic", re.compile(r"sk-ant-[A-Za-z0-9_-]{8,}")),
    ("chave OpenAI", re.compile(r"sk-proj-[A-Za-z0-9_-]{8,}")),
    ("chave Resend", re.compile(r"re_[A-Za-z0-9]{16,}")),
    ("chave AWS", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("token GitHub", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("URL Postgres com senha", re.compile(r"postgres(ql)?://[^\s:]+:[^\s@]+@")),
    ("PEM privado", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]

# Perigo no front. Cada um é localizador, não veredito.
PADROES_FRONT = [
    ("dangerouslySetInnerHTML", re.compile(r"dangerouslySetInnerHTML")),
    ("innerHTML", re.compile(r"\.innerHTML\s*=")),
    ("document.write", re.compile(r"document\.write\s*\(")),
    ("eval", re.compile(r"\beval\s*\(")),
    ("new Function", re.compile(r"new\s+Function\s*\(")),
    ("target=_blank sem rel", re.compile(r'target=["\']_blank["\'](?![^>]*rel=)')),
    ("localStorage", re.compile(r"localStorage\.")),
]

# Filtro cru do PostgREST: aceita STRING, não parâmetro. Input do usuário
# concatenado aqui é injetável de verdade (diferente de .eq(), que parametriza).
PADROES_FILTRO_CRU = [
    ("filtro .or() cru", re.compile(r"\.or\s*\(\s*(?:`[^`]*\$\{|[\"'][^\"']*[\"']\s*\+|[A-Za-z_$][\w$.]*\s*\+)")),
    ("filtro .filter() cru", re.compile(r"\.filter\s*\([^)]*?`[^`]*\$\{")),
    ("ilike com template", re.compile(r"\.i?like\s*\(\s*[^,]+,\s*`")),
]

# Marcadores de "isto é código de servidor" por padrão de framework. Só informam o
# inventário; a unidade auditável continua sendo o símbolo exportado.
MARCADORES_SERVIDOR = {
    "tanstack-start": re.compile(r"createServerFn\s*\("),
    "next-app": re.compile(r"['\"]use server['\"]|export\s+async\s+function\s+(GET|POST|PUT|PATCH|DELETE)\b"),
    "supabase-edge": re.compile(r"Deno\.serve\s*\(|serve\s*\("),
    "api-propria": re.compile(r"\.(get|post|put|patch|delete|use)\s*\(\s*['\"`]/"),
}

EXT_CODIGO = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}


def eprint(*a):
    print(*a, file=sys.stderr)


def run_safe(nome, fn, *args, **kwargs):
    """Um detector que estoura não derruba a rodada. Devolve (ok, resultado)."""
    try:
        return True, fn(*args, **kwargs)
    except Exception:
        eprint(f"[scanner] detector '{nome}' falhou:\n{traceback.format_exc()}")
        return False, None


# ---------------------------------------------------------------------------
# PERFIL
# ---------------------------------------------------------------------------

def carregar_perfil(caminho: Path) -> dict:
    if tomllib is None:
        raise SystemExit("Python 3.11+ necessário (tomllib). Atualize o Python.")
    with caminho.open("rb") as f:
        perfil = tomllib.load(f)
    raiz_decl = perfil.get("app", {}).get("raiz", ".")
    raiz = (caminho.parent / raiz_decl).resolve()
    if not raiz.is_dir():
        raise SystemExit(f"[app].raiz não existe: {raiz}")
    perfil["_raiz"] = raiz
    perfil["_perfil_path"] = caminho
    perfil["_hash"] = hashlib.sha256(caminho.read_bytes()).hexdigest()[:12]
    return perfil


def coletar(perfil: dict, chave: str) -> list[Path]:
    """Resolve os globs de [caminhos] em lista ordenada e deduplicada."""
    raiz: Path = perfil["_raiz"]
    ignorar = perfil.get("caminhos", {}).get("ignorar", [])
    padroes = perfil.get("caminhos", {}).get(chave, [])
    achados: set[Path] = set()
    for padrao in padroes:
        for p in raiz.glob(padrao):
            if not p.is_file():
                continue
            partes = set(p.parts)
            if any(ig in partes or ig == p.name for ig in ignorar):
                continue
            achados.add(p)
    return sorted(achados)


def rel(perfil: dict, p: Path) -> str:
    try:
        return p.relative_to(perfil["_raiz"]).as_posix()
    except ValueError:
        return p.as_posix()


def ler(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="replace")


# ---------------------------------------------------------------------------
# INVENTÁRIO DO BANCO (parseia as migrations)
# ---------------------------------------------------------------------------

# Esquema opcional, com ou sem aspas: `x`, `public.x`, `"public"."x"`, `crm.x`. É o formato
# que o `supabase db diff` e o pg_dump escrevem, e app grande guarda tabela fora do public.
SQ = r"(?:\"?[a-z_][a-z0-9_]*\"?\s*\.\s*)?\"?"
NOME_POLICY = r"(?:\"([^\"]+)\"|'([^']+)'|([^\s\"';]+))"

RE_CREATE_TABLE = re.compile(
    r"create\s+(?:(?:temp|temporary|unlogged)\s+)?table\s+(?:if\s+not\s+exists\s+)?"
    r"(?:\"?([a-z_][a-z0-9_]*)\"?\s*\.\s*)?\"?" + r"([a-z0-9_]+)\"?(?=\s*\(|\s+as\b|\s+partition\b)", re.I)
RE_DROP_TABLE = re.compile(r"\bdrop\s+table\s+(?:if\s+exists\s+)?([^;]+?)(?:\s+cascade|\s+restrict)?\s*;", re.I)
RE_DROP_VIEW = re.compile(
    r"\bdrop\s+(?:materialized\s+)?view\s+(?:if\s+exists\s+)?([^;]+?)(?:\s+cascade|\s+restrict)?\s*;", re.I)
RE_DROP_SCHEMA = re.compile(r"\bdrop\s+schema\s+(?:if\s+exists\s+)?\"?([a-z_][a-z0-9_]*)\"?[^;]*\bcascade\b", re.I)
RE_RENAME_TABLE = re.compile(
    r"alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(?:\"?[a-z_][a-z0-9_]*\"?\s*\.\s*)?\"?([a-z0-9_]+)\"?"
    r"\s+rename\s+to\s+\"?([a-z0-9_]+)", re.I)
RE_GRANT_EM_MASSA = re.compile(
    r"grant\s+[a-z, ]+?\s+on\s+all\s+(tables|sequences|functions|routines)\s+in\s+schema\s+"
    r"\"?([a-z_][a-z0-9_]*)\"?\s+to\s+([a-z_, \"]+)", re.I)
OBJETOS_EM_MASSA = {"tables", "sequences", "functions", "routines", "types", "schemas"}
RE_RLS_ON = re.compile(
    r"alter\s+table\s+(?:only\s+)?(?:if\s+exists\s+)?" + SQ + r"([a-z0-9_]+)\"?\s+enable\s+row\s+level\s+security",
    re.I)
RE_POLICY = re.compile(r"create\s+policy\s+" + NOME_POLICY + r"\s+on\s+" + SQ + r"([a-z0-9_]+)", re.I)
RE_DROP_POLICY = re.compile(
    r"drop\s+policy\s+(?:if\s+exists\s+)?" + NOME_POLICY + r"\s+on\s+" + SQ + r"([a-z0-9_]+)", re.I)
RE_FUNC = re.compile(
    r"create\s+(?:or\s+replace\s+)?function\s+" + SQ + r"([a-z0-9_]+)\"?\s*\(", re.I)
RE_VIEW = re.compile(
    r"create\s+(?:or\s+replace\s+)?view\s+" + SQ + r"([a-z0-9_]+)", re.I)
RE_TRIGGER = re.compile(
    r"create\s+(?:or\s+replace\s+)?(?:constraint\s+)?trigger\s+\"?([a-z0-9_]+)", re.I)
RE_ENUM = re.compile(
    r"create\s+type\s+" + SQ + r"([a-z0-9_]+)\"?\s+as\s+enum\s*\(([^)]*)\)", re.I | re.S)
RE_GRANT = re.compile(
    r"grant\s+([a-z, ]+)\s+on\s+(?:table\s+)?" + SQ + r"([a-z0-9_]+)\"?\s+to\s+([a-z_, ]+)",
    re.I)


def _nome_e_tabela(m) -> tuple[str, str]:
    """Nome e tabela de um match de RE_POLICY ou RE_DROP_POLICY."""
    return (m.group(1) or m.group(2) or m.group(3)), m.group(4).lower()
RE_BUCKET = re.compile(r"storage\.buckets", re.I)
RE_DOLLAR_TAG = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*\$|\$\$")
RE_PROXIMO_CREATE = re.compile(r"\bcreate\s+(or\s+replace\s+)?(function|table|view|policy|trigger|type|index)\b", re.I)


def _corpo_da_funcao(texto: str, inicio: int) -> str:
    """Devolve o texto de UM statement CREATE FUNCTION, do início ao `;` final.

    O corpo fica entre dois delimitadores dollar-quote iguais (`$$`, `$body$`, `$fn$`).
    `SECURITY DEFINER` e `SET search_path` podem vir antes OU depois do corpo, então o
    recorte vai até o ponto e vírgula que fecha o statement, depois do delimitador de
    fechamento.

    Sem delimitador (função SQL de uma linha, ou arquivo truncado), o recorte para no
    próximo `CREATE` ou em 4000 caracteres, o que vier primeiro. Cortar cego em 4000
    misturava duas funções vizinhas: a segunda emprestava `security definer` ou
    `set search_path` à primeira, e o detector errava nos dois sentidos.
    """
    janela = texto[inicio:inicio + 20000]
    m1 = RE_DOLLAR_TAG.search(janela)
    if m1:
        tag = m1.group(0)
        fim_tag = janela.find(tag, m1.end())
        if fim_tag != -1:
            ponto = janela.find(";", fim_tag + len(tag))
            if ponto != -1:
                return janela[:ponto + 1]
            return janela[:fim_tag + len(tag)]
    curto = janela[:4000]
    m2 = RE_PROXIMO_CREATE.search(curto, 8)
    return curto[:m2.start()] if m2 else curto


def _statement(texto: str, inicio: int, teto: int = 4000) -> str:
    """Recorta UM statement SQL, do início ao primeiro `;` fora de dollar-quote.

    Recorte cego de N caracteres invade o statement seguinte: uma policy emprestava o
    `using (true)` da vizinha e virava falso positivo de tautologia.
    """
    janela = texto[inicio:inicio + teto]
    i, n = 0, len(janela)
    while i < n:
        m = RE_DOLLAR_TAG.match(janela, i)
        if m:
            fim = janela.find(m.group(0), m.end())
            if fim == -1:
                return janela
            i = fim + len(m.group(0))
            continue
        if janela[i] == ";":
            return janela[:i + 1]
        i += 1
    return janela


def _esquemas_expostos(perfil: dict) -> set[str]:
    """Esquemas que a API do Supabase publica. Tabela fora deles não é alcançável pela chave anon.

    Ordem: o perfil declara (`[plataforma] esquemas_expostos`); senão, o `[api] schemas` do
    `supabase/config.toml` do repositório; senão, o padrão do Supabase.
    """
    import tomllib

    declarado = perfil.get("plataforma", {}).get("esquemas_expostos")
    if declarado:
        return {s.lower() for s in declarado}
    raiz: Path = perfil["_raiz"]
    for cfg in sorted(raiz.glob("**/supabase/config.toml")):
        if "node_modules" in cfg.parts:
            continue
        try:
            dados = tomllib.loads(cfg.read_text(encoding="utf-8"))
        except Exception:
            continue
        esquemas = dados.get("api", {}).get("schemas")
        if esquemas:
            return {s.lower() for s in esquemas}
    return {"public", "graphql_public"}


def inventario_banco(perfil: dict) -> dict:
    arquivos = coletar(perfil, "migrations")
    tabelas: dict[str, str] = {}
    rls_on: set[str] = set()
    policies: list[dict] = []
    drops: list[dict] = []
    funcoes: dict[str, dict] = {}
    views: list[dict] = []
    triggers: list[dict] = []
    enums: dict[str, list[str]] = {}
    grants: list[dict] = []
    definer_sem_searchpath: list[dict] = []
    tem_storage_bucket = False

    esquema_da_tabela: dict[str, str] = {}
    policy_dinamica: set[str] = set()
    grants_em_massa: list[dict] = []
    eventos: list[tuple] = []
    for i, arq in enumerate(arquivos):
        texto = _sem_comentario(ler(arq))
        nome_arq = rel(perfil, arq)
        linhas_por_pos = _mapa_linhas(texto)

        for m in RE_CREATE_TABLE.finditer(texto):
            eventos.append(((i, m.start()), "tab_create",
                            (m.group(2).lower(), (m.group(1) or "public").lower(), nome_arq)))
        for m in RE_DROP_TABLE.finditer(texto):
            nomes = [re.sub(r"^.*\.", "", n.strip().strip('"')).strip('"').lower()
                     for n in re.split(r",", m.group(1)) if n.strip()]
            eventos.append(((i, m.start()), "tab_drop", nomes))
        for m in RE_RENAME_TABLE.finditer(texto):
            eventos.append(((i, m.start()), "tab_rename", (m.group(1).lower(), m.group(2).lower())))
        for m in RE_DROP_SCHEMA.finditer(texto):
            eventos.append(((i, m.start()), "schema_drop", m.group(1).lower()))
        for m in RE_DROP_VIEW.finditer(texto):
            nomes = [re.sub(r"^.*\.", "", n.strip().strip('"')).strip('"').lower()
                     for n in re.split(r",", m.group(1)) if n.strip()]
            eventos.append(((i, m.start()), "view_drop", nomes))
        # RLS ligada em laço: `foreach t in array[...] loop execute format('alter table %I
        # enable row level security', t)`. Sem isto, tabela protegida vira "tabela sem RLS".
        for m in re.finditer(r"format\s*\(\s*'[^']*enable\s+row\s+level\s+security[^']*'", texto, re.I):
            ini = max(texto.rfind("do $", 0, m.start()), texto.rfind("do\n$", 0, m.start()), 0)
            fim = texto.find("end loop", m.end())
            janela = texto[ini:fim if fim != -1 else m.end() + 2000]
            nomes = {n.lower() for lista in re.findall(r"array\s*\[([^\]]*)\]", janela, re.I)
                     for n in re.findall(r"'([a-z0-9_]+)'", lista, re.I)}
            rls_on.update(nomes)
            if re.search(r"format\s*\(\s*'[^']*create\s+policy", janela, re.I):
                policy_dinamica.update(nomes)
        for m in RE_GRANT_EM_MASSA.finditer(texto):
            grants_em_massa.append({
                "objeto": m.group(1).lower(), "esquema": m.group(2).lower(),
                "para": [r.strip().strip('"').lower() for r in m.group(3).split(",") if r.strip()],
                "arquivo": nome_arq, "linha": linhas_por_pos(m.start()),
            })
        for m in RE_RLS_ON.finditer(texto):
            eventos.append(((i, m.start()), "rls_on", m.group(1).lower()))
        for m in RE_POLICY.finditer(texto):
            if texto[m.end():m.end() + 1] in (".", "%") or "%" in (m.group(3) or ""):
                continue
            # O que vem DEPOIS do nome da tabela: o nome da policy pode conter "for all".
            resto = _statement(texto, m.end())
            nome_pol, tabela_pol = _nome_e_tabela(m)
            eventos.append(((i, m.start()), "pol_create", {
                "nome": nome_pol,
                "tabela": tabela_pol,
                "arquivo": nome_arq,
                "linha": linhas_por_pos(m.start()),
                "comando": _comando_da_policy(resto),
                "para": _roles_da_policy(resto),
                "restritiva": bool(re.search(r"\bas\s+restrictive\b", resto, re.I)),
                "tem_using": bool(re.search(r"\busing\s*\(", resto, re.I)),
                "tem_with_check": bool(re.search(r"\bwith\s+check\s*\(", resto, re.I)),
                "tautologia": bool(re.search(r"(using|with\s+check)\s*\(\s*true\s*\)", resto, re.I)),
            }))
        for m in RE_DROP_POLICY.finditer(texto):
            nome_pol, tabela_pol = _nome_e_tabela(m)
            drops.append({"nome": nome_pol, "tabela": tabela_pol, "arquivo": nome_arq})
            eventos.append(((i, m.start()), "pol_drop", (nome_pol, tabela_pol)))
        for m in RE_FUNC.finditer(texto):
            nome = m.group(1).lower()
            corpo = _corpo_da_funcao(texto, m.start())
            definer = bool(re.search(r"security\s+definer", corpo, re.I))
            searchpath = bool(re.search(r"set\s+\"?search_path\"?", corpo, re.I))
            reg = funcoes.setdefault(nome, {
                "nome": nome, "definer": False, "search_path": False,
                "arquivos": [], "linha": linhas_por_pos(m.start()),
            })
            # A última definição vence: CREATE OR REPLACE posterior redefine a função.
            reg["definer"] = definer
            reg["search_path"] = searchpath
            reg["linha"] = linhas_por_pos(m.start())
            if nome_arq not in reg["arquivos"]:
                reg["arquivos"].append(nome_arq)
        for m in RE_VIEW.finditer(texto):
            trecho = _statement(texto, m.start())
            # Em Postgres 15+ a view roda com o privilégio do DONO (definer) a menos que
            # declare `security_invoker = true`. Ausência da cláusula é definer.
            invoker = bool(re.search(r"security_invoker\s*(?:=\s*(?:true|on)\s*)?[,)]", trecho, re.I))
            eventos.append(((i, m.start()), "view_create", {
                "nome": m.group(1).lower(), "arquivo": nome_arq,
                "linha": linhas_por_pos(m.start()),
                "definer": not invoker,
            }))
        for m in RE_TRIGGER.finditer(texto):
            triggers.append({"nome": m.group(1).lower(), "arquivo": nome_arq})
        for m in RE_ENUM.finditer(texto):
            valores = re.findall(r"'([^']+)'", m.group(2))
            enums[m.group(1).lower()] = valores
        for m in RE_GRANT.finditer(texto):
            if m.group(2).lower() in OBJETOS_EM_MASSA:
                continue
            grants.append({
                "privilegio": m.group(1).strip(), "tabela": m.group(2).lower(),
                "para": [r.strip() for r in m.group(3).split(",")],
                "arquivo": nome_arq, "linha": linhas_por_pos(m.start()),
            })
        if RE_BUCKET.search(texto):
            tem_storage_bucket = True

    dinamicas = set(rls_on)
    pol_final: dict[tuple[str, str], dict] = {}
    views_final: dict[str, dict] = {}
    for _, tipo, dado in sorted(eventos, key=lambda e: e[0]):
        if tipo == "tab_create":
            nome, esq, arq_ = dado
            tabelas.setdefault(nome, arq_)
            esquema_da_tabela.setdefault(nome, esq)
        elif tipo == "tab_drop":
            for n in dado:
                tabelas.pop(n, None)
                esquema_da_tabela.pop(n, None)
                rls_on.discard(n)
                for k in [k for k in pol_final if k[0] == n]:
                    pol_final.pop(k)
        elif tipo == "tab_rename":
            velho, novo = dado
            if velho in tabelas:
                tabelas[novo] = tabelas.pop(velho)
                esquema_da_tabela[novo] = esquema_da_tabela.pop(velho, "public")
            if velho in rls_on:
                rls_on.discard(velho)
                rls_on.add(novo)
            for k in [k for k in pol_final if k[0] == velho]:
                p = pol_final.pop(k)
                p["tabela"] = novo
                pol_final[(novo, k[1])] = p
        elif tipo == "schema_drop":
            for n in [n for n, e in esquema_da_tabela.items() if e == dado]:
                tabelas.pop(n, None)
                esquema_da_tabela.pop(n, None)
                rls_on.discard(n)
                for k in [k for k in pol_final if k[0] == n]:
                    pol_final.pop(k)
        elif tipo == "rls_on":
            rls_on.add(dado)
        elif tipo == "pol_create":
            pol_final[(dado["tabela"], dado["nome"])] = dado
        elif tipo == "pol_drop":
            pol_final.pop((dado[1], dado[0]), None)
        elif tipo == "view_create":
            views_final[dado["nome"]] = dado
        elif tipo == "view_drop":
            for n in dado:
                views_final.pop(n, None)
    rls_on |= dinamicas
    policies = list(pol_final.values())
    views = list(views_final.values())

    for f in funcoes.values():
        if f["definer"] and not f["search_path"]:
            definer_sem_searchpath.append({
                "funcao": f["nome"], "arquivo": f["arquivos"][-1], "linha": f["linha"],
            })

    # Policies empilhadas: no Postgres, permissivas na mesma tabela+comando são OR.
    # Uma policy ampla de staff alarga TODAS as outras daquela tabela, em silêncio.
    # Policy RESTRICTIVE combina com E, então não entra na conta.
    por_tabela_comando: dict[tuple, list[str]] = {}
    for p in policies:
        if p["restritiva"]:
            continue
        por_tabela_comando.setdefault((p["tabela"], p["comando"]), []).append(p["nome"])
    empilhadas = [
        {"tabela": t, "comando": c, "policies": ns}
        for (t, c), ns in sorted(por_tabela_comando.items()) if len(ns) > 1
    ]

    # Escrita sem trava. Em UPDATE e ALL sem WITH CHECK, o Postgres usa o USING como trava
    # (documentação do CREATE POLICY), então só falta trava quando não há nenhum dos dois.
    # Em INSERT o USING não se aplica e a documentação não define o que vale sem WITH CHECK:
    # continua acusado, porque ou libera qualquer linha ou não faz nada.
    escrita_sem_check = [
        {"policy": p["nome"], "tabela": p["tabela"], "comando": p["comando"],
         "arquivo": p["arquivo"], "linha": p["linha"]}
        for p in policies
        if (p["comando"] == "insert" and not p["tem_with_check"])
        or (p["comando"] in ("update", "all") and not p["tem_with_check"] and not p["tem_using"])
    ]

    # Tabela sem RLS só é aberta se alguém de fora tem permissão nela. Esquema exposto que
    # não é o public não ganha nada por padrão no Supabase: precisa de `grant usage` pra anon
    # ou authenticated. E tabela revogada dos dois está fechada mesmo sem RLS.
    expostos = _esquemas_expostos(perfil)
    tudo = "\n".join(_sem_comentario(ler(a)) for a in arquivos)
    com_uso = {"public"} | {
        m.group(1).lower() for m in re.finditer(
            r"grant\s+usage\s+on\s+schema\s+\"?([a-z_][a-z0-9_]*)\"?\s+to\s+([^;]+)", tudo, re.I)
        if re.search(r"\b(anon|authenticated|public)\b", m.group(2), re.I)}
    revogadas: dict[str, set[str]] = {}
    for m in re.finditer(
            r"revoke\s+[a-z, ]+?\s+on\s+(?:table\s+)?" + SQ + r"([a-z0-9_]+)\"?\s+from\s+([^;]+)", tudo, re.I):
        revogadas.setdefault(m.group(1).lower(), set()).update(
            r.strip().strip('"').lower() for r in m.group(2).split(","))
    fechada = lambda t: {"anon", "authenticated"} <= revogadas.get(t, set())
    tabelas_sem_rls = sorted(t for t in set(tabelas) - rls_on
                             if esquema_da_tabela.get(t, "public") in expostos
                             and esquema_da_tabela.get(t, "public") in com_uso
                             and not fechada(t))
    tabelas_com_rls_sem_policy = sorted(
        (rls_on & set(tabelas)) - {p["tabela"] for p in policies} - policy_dinamica)

    return {
        "arquivos_migration": len(arquivos),
        "tabelas": dict(sorted(tabelas.items())),
        "esquema_da_tabela": dict(sorted(esquema_da_tabela.items())),
        "esquemas_expostos": sorted(expostos),
        "grants_em_massa": grants_em_massa,
        "total_tabelas": len(tabelas),
        "rls_habilitado": sorted(rls_on),
        "total_rls": len(rls_on),
        "tabelas_sem_rls": tabelas_sem_rls,
        "tabelas_com_rls_sem_policy": tabelas_com_rls_sem_policy,
        "policies": policies,
        "total_policies": len(policies),
        "drop_policies": drops,
        "policies_empilhadas": empilhadas,
        "escrita_sem_with_check": escrita_sem_check,
        "policies_tautologicas": [p for p in policies if p["tautologia"]],
        "funcoes": sorted(funcoes.values(), key=lambda f: f["nome"]),
        "total_funcoes": len(funcoes),
        "total_definer": sum(1 for f in funcoes.values() if f["definer"]),
        "definer_sem_searchpath": definer_sem_searchpath,
        "views": views,
        "views_definer": [v for v in views if v["definer"]],
        "triggers": triggers,
        "total_triggers": len(triggers),
        "enums": enums,
        "grants": grants,
        "grants_para_anon": [g for g in grants if "anon" in g["para"]],
        "tem_storage_bucket": tem_storage_bucket,
    }


def _comando_da_policy(trecho: str) -> str:
    m = re.search(r"\bfor\s+(all|select|insert|update|delete)\b", trecho, re.I)
    return m.group(1).lower() if m else "all"


def _roles_da_policy(trecho: str) -> list[str]:
    m = re.search(r"\bto\s+([a-z_, \"]+?)(?:\s+using|\s+with|\s*;|\n)", trecho, re.I)
    if not m:
        return []
    return [r.strip().strip('"').lower() for r in m.group(1).split(",") if r.strip()]


def _mapa_linhas(texto: str):
    """Devolve fn(pos) -> número de linha (1-indexado)."""
    quebras = [i for i, ch in enumerate(texto) if ch == "\n"]

    def linha_de(pos: int) -> int:
        lo, hi = 0, len(quebras)
        while lo < hi:
            mid = (lo + hi) // 2
            if quebras[mid] < pos:
                lo = mid + 1
            else:
                hi = mid
        return lo + 1

    return linha_de


# ---------------------------------------------------------------------------
# INVENTÁRIO DO CÓDIGO
# ---------------------------------------------------------------------------

RE_EXPORT = re.compile(
    r"^export\s+(?:default\s+)?(?:const|let|function|async\s+function)\s+([A-Za-z0-9_$]+)", re.M)
RE_MIDDLEWARE_USO = re.compile(r"\.middleware\s*\(\s*\[([^\]]*)\]", re.S)
RE_RPC = re.compile(r"\.rpc\s*\(\s*[\"']([a-z0-9_]+)[\"']", re.I)


RE_ARQUIVO_DE_TESTE = re.compile(r"(\.test\.|\.spec\.|/__tests__/|/tests?/|/__mocks__/)", re.I)
# Rota que confere quem chama por sessão ou por guarda própria do projeto
# (`requireRole`, `requireAuth`, `withAuth`), e não por header ou assinatura.
RE_GUARDA_DE_ROTA = re.compile(
    r"\b(?:getUser|getSession|getServerSession|currentUser)\s*\(|\bauth\s*\(\s*\)|"
    r"\b(?:require|authenticate|authorize|autoriza|exige|resolveAuth|withAuth)[A-Za-z]*\s*\(|"
    r"\bverify(?:Auth|Token|Signature|Session|User|Jwt|Webhook|Request|Api|Cron)[A-Za-z]*\s*\(")


def _sem_comentario_js(texto: str) -> str:
    """Troca comentário `//` e `/* */` por espaço, respeitando string e template. Posição igual."""
    saida, i, n, aspa = list(texto), 0, len(texto), None
    while i < n:
        c = texto[i]
        if aspa:
            if c == "\\":
                i += 2
                continue
            if c == aspa:
                aspa = None
        elif c in "'\"`":
            aspa = c
        elif texto.startswith("//", i):
            fim = texto.find("\n", i)
            fim = n if fim == -1 else fim
            for j in range(i, fim):
                saida[j] = " "
            i = fim
            continue
        elif texto.startswith("/*", i):
            fim = texto.find("*/", i + 2)
            fim = n if fim == -1 else fim + 2
            for j in range(i, fim):
                if saida[j] != "\n":
                    saida[j] = " "
            i = fim
            continue
        i += 1
    return "".join(saida)


def inventario_codigo(perfil: dict) -> dict:
    import fnmatch
    priv = perfil.get("privilegio", {})
    nome_admin = priv.get("nome_do_client_privilegiado", "supabaseAdmin")
    re_admin = re.compile(re.escape(nome_admin))
    padrao = perfil.get("app", {}).get("padrao_servidor", "tanstack-start")
    re_marcador = MARCADORES_SERVIDOR.get(padrao)

    server_functions: list[dict] = []
    for arq in coletar(perfil, "server_functions"):
        texto = ler(arq)
        linha_de = _mapa_linhas(texto)
        exports = [(m.group(1), linha_de(m.start())) for m in RE_EXPORT.finditer(texto)]
        # Arquivo de servidor sem export nomeado (Edge Function com Deno.serve, handler
        # default anônimo) vira UMA unidade auditável: o próprio arquivo. Sem isto ele
        # sumia do universo e a prova de cobertura passava com um buraco.
        if not exports:
            exports = [("(arquivo)", 1)]
        usa_admin = bool(re_admin.search(texto))
        mids = sorted({
            t.strip() for m in RE_MIDDLEWARE_USO.finditer(texto)
            for t in m.group(1).split(",") if t.strip()
        })
        for nome, linha in exports:
            server_functions.append({
                "id": f"{rel(perfil, arq)}::{nome}",
                "arquivo": rel(perfil, arq),
                "simbolo": nome,
                "linha": linha,
                "usa_client_privilegiado": usa_admin,
                "tem_marcador_de_servidor": bool(re_marcador and re_marcador.search(texto)),
                "middlewares_no_arquivo": mids,
            })

    rotas_api: list[dict] = []
    for arq in coletar(perfil, "rotas_api"):
        texto = ler(arq)
        rotas_api.append({
            "id": rel(perfil, arq),
            "arquivo": rel(perfil, arq),
            "usa_client_privilegiado": bool(re_admin.search(texto)),
            "checa_bearer": bool(re.search(r"authorization|bearer", texto, re.I)),
            "checa_sessao": bool(RE_GUARDA_DE_ROTA.search(texto)),
            "verifica_assinatura": bool(re.search(
                r"constructEvent|verifyHeader|createHmac|timingSafeEqual|svix", texto, re.I)),
            "linhas": texto.count("\n") + 1,
        })

    middlewares: list[dict] = []
    for arq in coletar(perfil, "middlewares"):
        texto = ler(arq)
        linha_de = _mapa_linhas(texto)
        for m in RE_EXPORT.finditer(texto):
            middlewares.append({
                "simbolo": m.group(1), "arquivo": rel(perfil, arq),
                "linha": linha_de(m.start()),
            })

    # Sítios do client privilegiado, e se estão onde o perfil permite.
    permitido = priv.get("service_role_permitido_em", [])
    sitios_admin: list[dict] = []
    for chave in ("server_functions", "rotas_api", "middlewares", "frontend"):
        for arq in coletar(perfil, chave):
            if RE_ARQUIVO_DE_TESTE.search(arq.as_posix()):
                continue
            texto = _sem_comentario_js(ler(arq))
            if not re_admin.search(texto):
                continue
            r = rel(perfil, arq)
            ok = any(Path(r).match(pat) or fnmatch.fnmatch(r, pat) for pat in permitido)
            sitios_admin.append({
                "arquivo": r, "categoria": chave, "permitido_pelo_perfil": ok,
                "import_lazy": bool(re.search(r"await\s+import\s*\(", texto)),
            })
    vistos = set()
    sitios_dedup = []
    for s in sorted(sitios_admin, key=lambda x: x["arquivo"]):
        if s["arquivo"] in vistos:
            continue
        vistos.add(s["arquivo"])
        sitios_dedup.append(s)

    rpcs_chamadas: set[str] = set()
    for chave in ("server_functions", "rotas_api", "middlewares", "frontend"):
        for arq in coletar(perfil, chave):
            for m in RE_RPC.finditer(_sem_comentario_js(ler(arq))):
                rpcs_chamadas.add(m.group(1).lower())

    testes = [rel(perfil, p) for p in coletar(perfil, "testes")]

    return {
        "padrao_servidor": padrao,
        "server_functions": server_functions,
        "total_server_functions": len(server_functions),
        "arquivos_server_functions": len({s["arquivo"] for s in server_functions}),
        "rotas_api": rotas_api,
        "total_rotas_api": len(rotas_api),
        "middlewares": middlewares,
        "sitios_client_privilegiado": sitios_dedup,
        "total_sitios_privilegiado": len(sitios_dedup),
        "privilegio_fora_do_permitido": [s for s in sitios_dedup if not s["permitido_pelo_perfil"]],
        "rpcs_chamadas": sorted(rpcs_chamadas),
        "testes": testes,
        "total_testes": len(testes),
    }


def _jwt_demo_do_supabase(jwt: str) -> bool:
    """A chave de demonstração do Supabase CLI (`iss: supabase-demo`) é pública por desenho."""
    import base64
    try:
        meio = jwt.split(".")[1]
        dado = base64.urlsafe_b64decode(meio + "=" * (-len(meio) % 4)).decode("utf-8", "replace")
    except Exception:
        return False
    return "supabase-demo" in dado


def detectores_mecanicos(perfil: dict, banco: dict, codigo: dict) -> dict:
    """Achados que NÃO precisam de julgamento. Cada um tem arquivo e linha."""
    achados: list[dict] = []

    def add(regra, severidade, titulo, arquivo, linha=None, detalhe="", dimensao="seguranca"):
        achados.append({
            "regra": regra, "severidade": severidade, "titulo": titulo,
            "arquivo": arquivo, "linha": linha, "detalhe": detalhe,
            "dimensao": dimensao, "origem": "mecanico",
        })

    # 1. Tabela sem RLS, só em esquema que a API expõe
    esquemas = banco.get("esquema_da_tabela", {})
    for t in banco["tabelas_sem_rls"]:
        qual = t if esquemas.get(t, "public") == "public" else f"{esquemas[t]}.{t}"
        add("rls-ausente", "critico", f"Tabela `{qual}` sem RLS habilitado",
            banco["tabelas"].get(t, "?"),
            detalhe="Sem RLS, qualquer portador da anon key lê e escreve a tabela inteira.")

    # 2. RLS ligado e zero policy = deny-all silencioso (ou bug)
    for t in banco["tabelas_com_rls_sem_policy"]:
        add("rls-sem-policy", "medio", f"Tabela `{t}` com RLS e nenhuma policy",
            banco["tabelas"].get(t, "?"),
            detalhe="Deny-all pra quem não é service_role. Pode ser deliberado, ou pode ser "
                    "leitura quebrada em silêncio: o RLS devolve zero linha SEM erro, e zero "
                    "linha pode estar sendo lido como estado válido.")

    # 3. Tautologia
    for p in banco["policies_tautologicas"]:
        add("policy-tautologica", "alto", f"Policy `{p['nome']}` em `{p['tabela']}` usa true",
            p["arquivo"], p["linha"],
            detalhe=f"Comando {p['comando'].upper()}, papéis "
                    f"{', '.join(p['para']) if p['para'] else 'não declarados'}. "
                    "Só se justifica se o dado é público por natureza.")

    # 4. Escrita sem WITH CHECK
    for p in banco["escrita_sem_with_check"]:
        add("escrita-sem-with-check", "alto",
            f"Policy `{p['policy']}` ({p['comando'].upper()}) em `{p['tabela']}` sem WITH CHECK",
            p["arquivo"], p["linha"],
            detalhe="Nenhuma trava sobre a linha gravada. Em INSERT só o WITH CHECK confere o "
                    "que entra; em UPDATE e ALL o Postgres usaria o USING no lugar dele, mas "
                    "esta policy não tem nenhum dos dois. Declarar `with check (...)` com a "
                    "mesma regra de dono que a leitura usa.")

    # 5. DEFINER sem search_path
    for f in banco["definer_sem_searchpath"]:
        add("definer-sem-search-path", "alto",
            f"Função `{f['funcao']}` é SECURITY DEFINER sem `set search_path`",
            f["arquivo"], f["linha"],
            detalhe="Definer roda com o poder do dono e atravessa o RLS. Sem search_path fixo, "
                    "é vetor de escalada de privilégio em Postgres.")

    # 5b. Função SEM search_path, mesmo não sendo definer. O advisor do Supabase pergunta
    # "tem search_path mutável?", que é mais amplo que "é definer sem search_path?".
    # Definer sem search_path é escalada; não-definer sem search_path é hardening.
    for f in banco["funcoes"]:
        if not f["search_path"] and not f["definer"]:
            add("search-path-mutavel", "baixo",
                f"Função `{f['nome']}` sem `set search_path` fixo",
                f["arquivos"][-1] if f["arquivos"] else "?", f.get("linha"),
                detalhe="Não é SECURITY DEFINER, então o risco é menor. Fixar o search_path é "
                        "hardening barato e evita surpresa se a função virar definer depois. "
                        "Conferir contra o advisor do banco: leitura de migration não vê o "
                        "estado real.")

    # 6. View definer
    for v in banco["views_definer"]:
        add("view-definer", "alto", f"View `{v['nome']}` com security definer",
            v["arquivo"], v["linha"], detalhe="View definer fura o RLS de quem consulta.")

    # 7. Grant direto pra anon
    for g in banco["grants_para_anon"]:
        add("grant-anon", "alto",
            f"GRANT {g['privilegio']} em `{g['tabela']}` para anon",
            g["arquivo"], g["linha"],
            detalhe="Grant direto pro papel anônimo depende inteiramente de o RLS estar certo.")

    # 7b. Grant em massa pro visitante: é o padrão do Supabase, então sozinho não é
    # brecha. Vira brecha somado a tabela sem RLS no mesmo esquema, e é por isso que aparece.
    for g in banco.get("grants_em_massa", []):
        if "anon" in g["para"] or "public" in g["para"]:
            add("grant-anon-em-massa", "medio",
                f"GRANT em todas as {g['objeto']} do esquema `{g['esquema']}` para o visitante",
                g["arquivo"], g["linha"],
                detalhe="É o padrão do Supabase e, sozinho, não expõe nada: quem barra é a RLS. "
                        "Por isso qualquer tabela deste esquema criada sem RLS fica aberta pra "
                        "chave anon no mesmo instante. Conferir junto com os achados de RLS "
                        "ausente, e revogar de anon nos esquemas que a API não precisa servir.")

    # 8. Policy empilhada (permissivas são OR)
    for e in banco["policies_empilhadas"]:
        add("policy-empilhada", "medio",
            f"`{e['tabela']}` tem {len(e['policies'])} policies de {e['comando'].upper()}",
            banco["tabelas"].get(e["tabela"], "?"),
            detalhe="No Postgres, policies permissivas na mesma tabela e comando se combinam "
                    "com OU. Uma policy ampla (de staff, por exemplo) alarga todas as outras "
                    f"em silêncio. Policies: {', '.join(e['policies'])}.")

    # 9. RPC chamada e não definida
    definidas = {f["nome"] for f in banco["funcoes"]}
    for nome in sorted(set(codigo["rpcs_chamadas"]) - definidas):
        add("rpc-fantasma", "medio", f"App chama a RPC `{nome}`, que não existe nas migrations",
            "codigo", detalhe="Ou a função foi criada à mão em produção (o repo e o banco "
                              "divergiram), ou a chamada está morta e falha em runtime.")

    # 10. Client privilegiado fora do permitido pelo perfil.
    # Severidade calibrada pela CATEGORIA, não pelo simples fato de estar fora da lista:
    # service_role num componente de tela é crítico e óbvio; num arquivo de servidor que
    # o perfil não previu é suspeita que exige conferir o grafo de import. Sem essa
    # calibragem o relatório nasce com enxurrada de crítico falso e perde a confiança do
    # leitor no primeiro minuto, o que é pior que não ter relatório.
    for s in codigo["privilegio_fora_do_permitido"]:
        if s["categoria"] == "frontend":
            add("privilegio-no-frontend", "critico",
                f"Client privilegiado referenciado em arquivo de tela: `{s['arquivo']}`",
                s["arquivo"],
                detalhe="Arquivo de frontend vai pro bundle do navegador. Se a chave que ignora "
                        "todo o RLS for realmente usada aqui, e não só citada em comentário, é "
                        "acesso total ao banco pra qualquer visitante.")
        else:
            add("privilegio-fora-do-perfil", "medio",
                f"Client privilegiado em `{s['arquivo']}`, caminho não previsto no perfil",
                s["arquivo"],
                detalhe="Pode ser legítimo (arquivo de servidor que o perfil não listou) ou pode "
                        "ser alcançável pelo bundle do cliente. CONFIRMAR O GRAFO DE IMPORT: "
                        "quem importa este arquivo, e algum desses caminhos chega no navegador? "
                        + ("Usa `await import()` lazy, o que ajuda mas não prova. "
                           if s["import_lazy"] else "")
                        + "Se for legítimo, acrescentar o caminho em "
                          "[privilegio].service_role_permitido_em do perfil.")

    # 11. Rota de API sem verificação aparente
    for r in codigo["rotas_api"]:
        if not r["checa_bearer"] and not r["verifica_assinatura"] and not r.get("checa_sessao"):
            add("rota-api-sem-verificacao", "alto",
                f"Rota `{Path(r['arquivo']).name}` sem bearer, sessão nem verificação de assinatura",
                r["arquivo"],
                detalhe="Rota de API alcançável sem login e sem segredo. Se ela escreve ou "
                        "revela dado, é porta aberta. Se é pública por desenho (descadastro, "
                        "captura de lead), o token precisa de HMAC, expiração e uso único.")

    # 12. Headers de segurança ausentes
    for cfg in coletar(perfil, "config_deploy"):
        texto = ler(cfg)
        faltando = [h for h in HEADERS_ESPERADOS if h.lower() not in texto.lower()]
        if faltando:
            alvo = Path(rel(perfil, cfg)).parts
            qual = alvo[1] if len(alvo) > 1 else alvo[0]
            add("headers-ausentes", "medio" if len(faltando) < len(HEADERS_ESPERADOS) else "alto",
                f"{len(faltando)} de {len(HEADERS_ESPERADOS)} headers de segurança ausentes "
                f"em {qual}",
                rel(perfil, cfg), detalhe="Faltando: " + ", ".join(faltando)
                + ". Subir a CSP primeiro em Report-Only pra mapear violação sem quebrar a tela.")

    # 13. Segredo aparente no código (NUNCA gravamos o valor). Arquivo de teste fica de
    # fora: `postgres://user:senha@localhost` de fixture não é credencial de ninguém.
    for chave in ("server_functions", "rotas_api", "middlewares", "frontend"):
        for arq in coletar(perfil, chave):
            if RE_ARQUIVO_DE_TESTE.search(arq.as_posix()):
                continue
            texto = ler(arq)
            linha_de = _mapa_linhas(texto)
            for tipo, rx in PADROES_SEGREDO:
                for m in rx.finditer(texto):
                    if tipo.startswith("JWT") and _jwt_demo_do_supabase(m.group(0)):
                        continue
                    add("segredo-hardcoded", "critico",
                        f"Possível {tipo} literal no código", rel(perfil, arq),
                        linha_de(m.start()),
                        detalhe="Valor MASCARADO de propósito. Se confirmado: rotacionar a chave "
                                "no provedor. Trocar de lugar não resolve, porque ela segue no "
                                "histórico do Git.")

    # 14. Padrões de front (localizador, o agente julga)
    front_hits: list[dict] = []
    for arq in coletar(perfil, "frontend"):
        texto = _sem_comentario_js(ler(arq))
        linha_de = _mapa_linhas(texto)
        for tipo, rx in PADROES_FRONT:
            for m in rx.finditer(texto):
                # saída que passa por sanitizador na mesma linha não é render cru
                linha_toda = texto[texto.rfind("\n", 0, m.start()) + 1:texto.find("\n", m.end())]
                if re.search(r"DOMPurify|sanitize|safeJson|escapeHtml|xss\(", linha_toda, re.I):
                    continue
                front_hits.append({"tipo": tipo, "arquivo": rel(perfil, arq),
                                   "linha": linha_de(m.start())})
    for h in front_hits:
        if h["tipo"] in ("dangerouslySetInnerHTML", "innerHTML", "document.write", "eval",
                         "new Function"):
            add("render-inseguro", "alto",
                f"{h['tipo']} em {Path(h['arquivo']).name}", h["arquivo"], h["linha"],
                detalhe="Se o conteúdo vem do usuário, do banco ou da IA, é XSS armazenado. "
                        "Se é estático e escrito pelo time (script inline, CSS de componente), "
                        "é legítimo. CONFIRMAR A ORIGEM DO DADO, não o padrão.")

    # 15. Filtro cru do PostgREST (injeção real nesta stack)
    for chave in ("server_functions", "rotas_api"):
        for arq in coletar(perfil, chave):
            texto = ler(arq)
            linha_de = _mapa_linhas(texto)
            texto = _sem_comentario_js(texto)
            for tipo, rx in PADROES_FILTRO_CRU:
                for m in rx.finditer(texto):
                    add("filtro-cru-postgrest", "medio",
                        f"{tipo} em {Path(rel(perfil, arq)).name}",
                        rel(perfil, arq), linha_de(m.start()),
                        detalhe="`.or()` e `.filter()` recebem STRING de filtro, não parâmetro. "
                                "Input do usuário concatenado aqui é injetável de verdade, ao "
                                "contrário de `.eq()`, que parametriza. Conferir se o valor vem "
                                "de enum ou allow-list.")

    # 16. Lacuna de teste de segurança
    nomes_teste = " ".join(codigo["testes"]).lower()
    for alvo, termo in [("RLS e policy", "rls"), ("webhook", "webhook"),
                        ("autorização", "autoriz"), ("isolamento entre usuários", "isolament")]:
        if termo not in nomes_teste:
            add("teste-de-seguranca-ausente", "medio",
                f"Nenhum teste cobrindo {alvo}", "testes", dimensao="corretude",
                detalhe=f"{codigo['total_testes']} arquivos de teste, nenhum com '{termo}' no "
                        "nome. Achado corrigido sem teste é achado que volta.")

    # 17. Resiliência da plataforma
    plat = perfil.get("plataforma", {})
    if plat.get("plano_banco") in ("free", "desconhecido"):
        sev = "critico" if plat.get("migration_aplicada_a_mao") else "alto"
        add("backup-incerto", sev,
            f"Plano do banco '{plat.get('plano_banco')}': backup automático não confirmado",
            "perfil.toml",
            detalhe="Plano gratuito costuma não ter backup automático e pausar o projeto por "
                    "inatividade. Combinado com migration aplicada à mão em produção, uma "
                    "migration errada não tem ponto de restauração, e o estrago é perda de dado "
                    "pessoal de cliente real, que não tem rollback. CONFERIR O PLANO primeiro.")

    git = perfil.get("git", {})
    if git.get("push_direto_na_main") and not git.get("tem_gate_de_ci"):
        add("sem-gate-de-ci", "medio", "Push direto na main sem gate de CI", ".github",
            detalhe="Toda verificação depende de rodar `tsc --noEmit` e `build` à mão e não "
                    "esquecer. Bundler não faz typecheck: build verde não prova tipo.")

    ia = perfil.get("ia", {})
    if ia.get("usa_llm"):
        add("llm-superficie", "medio",
            "App chama LLM: superfície de injeção de prompt e de custo",
            ia.get("handler", "?"),
            detalhe="Auditar: injeção de prompt extraindo instrução interna, dado privado indo "
                    "pro provedor sem necessidade, saída renderizada como HTML, e chamada cara "
                    "sem cota (exaustão aqui vira fatura, não queda).")
        if ia.get("a_ia_decide_algo_sensivel"):
            add("llm-decide", "alto", "Saída da IA usada em decisão sensível",
                ia.get("handler", "?"),
                detalhe="Resposta de LLM nunca deve ser fonte de verdade pra cobrança, permissão "
                        "ou estado de cobertura.")

    try:
        detectores_de_escopo(perfil, banco, add)
    except Exception as e:
        eprint(f"[scanner] detectores_de_escopo falhou: {e!r}")

    return {"achados": achados, "front_hits": front_hits}


# ---------------------------------------------------------------------------
# DETECTORES DE ESCOPO E CORRETUDE
# Nasceram da leitura linha a linha de um SaaS real de gestão de clientes (Órbita, MIT,
# github.com/felipefernandees/orbita), em 23/09/2026. Cada um é um buraco que existia lá.
# ---------------------------------------------------------------------------

RE_NOME_DE_PAPEL = re.compile(r"(^|_)(role|roles|papel|papeis)(_|$)", re.I)
RE_PREFIXO_DE_PAPEL = re.compile(r"(^|_)(is|eh|has|tem)_", re.I)
RE_PALAVRA_PAPEL = re.compile(r"\b(role|roles|papel|papeis)\b", re.I)
RE_LITERAL_SQL = re.compile(r"'(?:[^']|'')*'")
RE_REF_TABELA = re.compile(r"\b(?:from|join)\s+" + r"(?:\"?(?:public|storage|auth)\"?\s*\.\s*)?\"?" + r"([a-z0-9_]+)", re.I)
RE_SUFIXO_NAO_SENSIVEL = re.compile(r"_(count|qtd|total|type|tipo|id|at|em|expires|expira|hash_alg)$", re.I)
# Apagar a organização inteira leva o histórico junto por desenho: é o desmonte do cliente,
# e não o dado sumindo por baixo de quem ainda usa o sistema.
RAIZES_DE_INQUILINO = {
    "organizations", "organization", "orgs", "org", "tenants", "tenant", "workspaces",
    "workspace", "companies", "company", "accounts", "account", "teams", "team",
}
TOKENS_NAO_HISTORICO = {"avisos", "aviso", "notices", "notifications", "notificacoes", "alertas", "alerts", "push"}
RE_FLAG_DESATIVACAO = re.compile(
    r"^(active|is_active|ativo|desativado|disabled|deleted_at|excluido_em|archived_at)$", re.I)
RE_COL_SENSIVEL = re.compile(
    r"(^|_)(cpf|cnpj|rg|salario|salary|hourly|valor_hora|custo|senha|password|secret|segredo|"
    r"token|nascimento|telefone|phone|celular|whatsapp|email|endereco|address)(_|$)", re.I)
RE_TABELA_ABRE = re.compile(
    r"create\s+table\s+(?:if\s+not\s+exists\s+)?" + SQ + r"([a-z0-9_]+)\"?\s*\(", re.I)
RE_ALTER_TABELA = re.compile(
    r"alter\s+table\s+(?:only\s+)?(?:if\s+exists\s+)?" + SQ + r"([a-z0-9_]+)\"?\s+add\s+", re.I)
RE_FK_DE_TABELA = re.compile(
    r"foreign\s+key\s*\(\s*\"?([a-z0-9_]+)\"?\s*\)\s*references\s+" + SQ + r"([a-z0-9_]+)", re.I)
RE_FK_DE_COLUNA = re.compile(r"\breferences\s+" + SQ + r"([a-z0-9_]+)", re.I)
RE_ON_DELETE = re.compile(r"on\s+delete\s+(cascade|set\s+null|set\s+default|restrict|no\s+action)", re.I)
RE_ADD_COLUNA = re.compile(r"add\s+column\s+(?:if\s+not\s+exists\s+)?\"?([a-z0-9_]+)", re.I)
RE_GRANT_OU_REVOKE = re.compile(r"\b(grant|revoke)\s", re.I)
RE_ALVO_FUNCAO = re.compile(r"\bon\s+function\s+" + SQ + r"([a-z0-9_]+)", re.I)
RE_ADD_VALUE = re.compile(r"alter\s+type\s+" + SQ + r"([a-z0-9_]+)\"?\s+add\s+value", re.I)
RE_COMENTARIO_SQL = re.compile(r"--[^\n]*")
RE_UID_EMBRULHADO = re.compile(r"\(\s*select\s+auth\.uid\(\)\s*(?:as\s+\w+\s*)?\)", re.I)
RE_CONVITE = re.compile(r"invit|convite", re.I)
TOKENS_HISTORICO = {
    "horas", "hours", "apontamentos", "pagamentos", "payments", "faturas", "invoices", "creditos",
    "credits", "lancamentos", "ledger", "transacoes", "transactions", "extrato", "extratos",
    "consumo", "entries",
}
PARES_INTERVALO = [
    ("started_at", "ended_at"), ("start_at", "end_at"), ("starts_at", "ends_at"),
    ("inicio", "fim"), ("data_inicio", "data_fim"), ("inicia_em", "termina_em"),
    ("valid_from", "valid_to"), ("vigencia_inicio", "vigencia_fim"),
]
PALAVRAS_DE_RESTRICAO = {"constraint", "primary", "unique", "check", "foreign", "exclude", "like"}
PAPEIS_DO_BANCO = {"anon", "authenticated", "public", "service_role", "postgres", "authenticator"}


def _entre_parenteses(texto: str, abre: int) -> str:
    """Conteúdo entre o `(` na posição `abre` e o `)` que fecha ele."""
    nivel = 0
    for i in range(abre, min(len(texto), abre + 20000)):
        if texto[i] == "(":
            nivel += 1
        elif texto[i] == ")":
            nivel -= 1
            if nivel == 0:
                return texto[abre + 1:i]
    return texto[abre + 1:abre + 20000]


def _partes_de_topo(corpo: str) -> list[str]:
    """Divide o corpo de um CREATE TABLE nas vírgulas de nível zero."""
    partes, nivel, atual = [], 0, []
    for ch in corpo:
        if ch == "(":
            nivel += 1
        elif ch == ")":
            nivel -= 1
        if ch == "," and nivel == 0:
            partes.append("".join(atual).strip())
            atual = []
        else:
            atual.append(ch)
    if "".join(atual).strip():
        partes.append("".join(atual).strip())
    return partes


def _sem_comentario(texto: str) -> str:
    """Troca comentário de linha por espaços do mesmo tamanho: a posição e a linha não mudam."""
    return RE_COMENTARIO_SQL.sub(lambda m: " " * len(m.group(0)), texto)


def _sem_casca(x: str) -> str:
    x = x.strip()
    while x.startswith("(") and _entre_parenteses(x, 0) == x[1:-1]:
        x = x[1:-1].strip()
    return x


def _disjuncoes(expr: str) -> list[str]:
    """Divide uma expressão nos OR de nível zero."""
    expr = _sem_casca(expr)
    partes, nivel, inicio, i = [], 0, 0, 0
    baixo = expr.lower()
    while i < len(expr):
        ch = expr[i]
        if ch == "(":
            nivel += 1
        elif ch == ")":
            nivel -= 1
        elif nivel == 0 and baixo.startswith(" or ", i):
            partes.append(_sem_casca(expr[inicio:i]))
            inicio = i + 4
            i += 4
            continue
        i += 1
    partes.append(_sem_casca(expr[inicio:]))
    return partes


def _expressao_apos(trecho: str, palavra: str) -> str | None:
    m = re.search(palavra + r"\s*\(", trecho, re.I)
    if not m:
        return None
    return _entre_parenteses(trecho, m.end() - 1)


def _papeis_do_comando(trecho: str, palavra: str) -> set[str]:
    """Papéis depois do último `to` (grant) ou `from` (revoke) de um statement."""
    m = None
    for m in re.finditer(rf"\b{palavra}\s+([a-z_,\s\"]+?)\s*(?:;|$|\bcascade\b|\brestrict\b|\bwith\b|\bgranted\b)",
                         trecho, re.I):
        pass
    if not m:
        return set()
    return {r.strip().strip('"').lower() for r in m.group(1).split(",") if r.strip()}


def _funcoes_do_comando(st: str) -> list[str]:
    """Todas as funções de um GRANT ou REVOKE `on function a(), b()`, não só a primeira."""
    m = re.search(r"\bon\s+function\s+(.+?)\s+(?:from|to)\s", st, re.I | re.S)
    if not m:
        return []
    nomes = []
    for item in _partes_de_topo(m.group(1)):
        n = re.match(SQ + r"([a-z0-9_]+)", item.strip(), re.I)
        if n:
            nomes.append(n.group(1).lower())
    return nomes


def _alcanca_anon(papeis) -> bool:
    """Policy sem TO vale para PUBLIC, e PUBLIC inclui anon."""
    return not papeis or "anon" in papeis or "public" in papeis


def detectores_de_escopo(perfil: dict, banco: dict, add) -> None:
    textos = [(rel(perfil, a), ler(a)) for a in coletar(perfil, "migrations")]
    limpos = [(n, _sem_comentario(t)) for n, t in textos]

    # Estrutura: colunas, FKs e CHECKs de cada tabela, e a ÚLTIMA definição de cada função.
    tabelas: dict[str, dict] = {}
    funcoes: dict[str, dict] = {}
    for nome_arq, texto in limpos:
        linha_de = _mapa_linhas(texto)
        for m in RE_TABELA_ABRE.finditer(texto):
            corpo = _entre_parenteses(texto, m.end() - 1)
            t = tabelas.setdefault(m.group(1).lower(), {"colunas": {}, "fks": [], "checks": []})
            t.update({"arquivo": nome_arq, "linha": linha_de(m.start())})
            for p in _partes_de_topo(corpo):
                tokens = p.replace('"', "").split()
                if not tokens:
                    continue
                if re.search(r"\bcheck\s*\(", p, re.I):
                    t["checks"].append(p)
                if tokens[0].lower() in PALAVRAS_DE_RESTRICAO:
                    fk = RE_FK_DE_TABELA.search(p)
                    if fk:
                        od = RE_ON_DELETE.search(p)
                        t["fks"].append((fk.group(1).lower(), fk.group(2).lower(),
                                         od.group(1).lower() if od else ""))
                    continue
                col = tokens[0].lower()
                t["colunas"][col] = p
                fk = RE_FK_DE_COLUNA.search(p)
                if fk:
                    od = RE_ON_DELETE.search(p)
                    t["fks"].append((col, fk.group(1).lower(), od.group(1).lower() if od else ""))
        for m in RE_FUNC.finditer(texto):
            corpo = _corpo_da_funcao(texto, m.start())
            abre = texto.find("(", m.end() - 1)
            funcoes[m.group(1).lower()] = {
                "arquivo": nome_arq, "linha": linha_de(m.start()), "corpo": corpo,
                "params": _entre_parenteses(texto, abre).lower() if abre != -1 else "",
                "definer": bool(re.search(r"security\s+definer", corpo, re.I)),
                "trigger": bool(re.search(r"returns\s+trigger", corpo, re.I)),
                "sem_texto": RE_LITERAL_SQL.sub("''", corpo),
            }
    # Estado final de EXECUTE por função, na ordem em que os comandos aparecem: um GRANT
    # posterior reabre o que um REVOKE anterior fechou.
    revogado: dict[str, set[str]] = {}
    explicito: dict[str, set[str]] = {}
    for nome_arq, texto in limpos:
        for m in RE_ALTER_TABELA.finditer(texto):
            t = tabelas.get(m.group(1).lower())
            if t is None:
                continue
            st = _statement(texto, m.start())
            col = RE_ADD_COLUNA.match(st, m.end() - m.start())
            if col:
                t["colunas"].setdefault(col.group(1).lower(), st)
            if re.search(r"\bcheck\s*\(", st, re.I):
                t["checks"].append(st)
            fk = RE_FK_DE_TABELA.search(st)
            if fk:
                od = RE_ON_DELETE.search(st)
                t["fks"].append((fk.group(1).lower(), fk.group(2).lower(), od.group(1).lower() if od else ""))
        for m in RE_GRANT_OU_REVOKE.finditer(texto):
            st = _statement(texto, m.start())
            for nome_f in _funcoes_do_comando(st):
                estado = revogado.setdefault(nome_f, set())
                if m.group(1).lower() == "revoke":
                    papeis_r = _papeis_do_comando(st, "from")
                    estado.update(papeis_r)
                    explicito.get(nome_f, set()).difference_update(papeis_r)
                else:
                    papeis_g = _papeis_do_comando(st, "to")
                    estado.difference_update(papeis_g)
                    explicito.setdefault(nome_f, set()).update(papeis_g & {"anon", "authenticated"})
    rls_on = set(banco.get("rls_habilitado", []))

    def fechada_pra_visitante(nome: str) -> bool:
        # No Supabase a função nasce com EXECUTE para PUBLIC e, por default privileges, para anon.
        return {"public", "anon"} <= revogado.get(nome, set())

    # 1. Helper de papel que ignora a flag de desativação.
    flags = {t: [c for c in d["colunas"] if RE_FLAG_DESATIVACAO.match(c)] for t, d in tabelas.items()}
    flags = {t: fs for t, fs in flags.items() if fs}
    for nome, f in sorted(funcoes.items()):
        # Nome de papel decide sozinho; prefixo is_/eh_/has_/tem_ só conta se a função olha quem
        # está logado ou fala de papel no corpo, senão é pergunta sobre o dado (has_open_invoices).
        if not (RE_NOME_DE_PAPEL.search(nome)
                or (RE_PREFIXO_DE_PAPEL.search(nome)
                    and ("auth.uid()" in f["corpo"].lower() or RE_PALAVRA_PAPEL.search(f["sem_texto"])))):
            continue
        lidas = {x.lower() for x in RE_REF_TABELA.findall(f["corpo"])} & set(flags)
        for tabela in sorted(lidas):
            fs = flags[tabela]
            if not any(re.search(rf"\b{c}\b", f["sem_texto"], re.I) for c in fs):
                add("papel-ignora-desativacao", "alto",
                    f"Função `{nome}` decide papel lendo `{tabela}` sem olhar `{fs[0]}`",
                    f["arquivo"], f["linha"],
                    detalhe=f"`{tabela}` tem `{', '.join(fs)}`, mas a função que responde o papel "
                            "não filtra por ela. Desativar a pessoa só esconde a tela: a policy que "
                            "usa esta função continua liberando o banco. Filtrar a flag DENTRO "
                            "da função.")

    # 2. Coluna sensível liberada por GRANT de coluna (inclusive com vários privilégios no mesmo GRANT).
    for nome_arq, texto in limpos:
        linha_de = _mapa_linhas(texto)
        for m in RE_GRANT_OU_REVOKE.finditer(texto):
            if m.group(1).lower() != "grant":
                continue
            st = _statement(texto, m.start())
            alvo_tab = re.search(r"\bon\s+(?:table\s+)?" + SQ + r"([a-z0-9_]+)", st, re.I)
            if not alvo_tab or re.match(r"\s*function\b", st[alvo_tab.start() + 3:], re.I):
                continue
            colunas = [c.strip().strip('"').lower()
                       for lista in re.findall(r"\bselect\s*\(([^)]*)\)", st, re.I)
                       for c in lista.split(",")]
            sensiveis = [c for c in colunas
                         if RE_COL_SENSIVEL.search(c) and not RE_SUFIXO_NAO_SENSIVEL.search(c)]
            alvo = sorted(_papeis_do_comando(st, "to") & {"anon", "authenticated", "public"})
            if sensiveis and alvo:
                add("coluna-sensivel-exposta", "alto",
                    f"GRANT de `{', '.join(sensiveis)}` em `{alvo_tab.group(1)}` para {', '.join(alvo)}",
                    nome_arq, linha_de(m.start()),
                    detalhe="Privilégio de coluna libera o valor pra todo mundo que a RLS da "
                            "tabela deixa ver a LINHA. Se a policy abre a linha pra colegas, o "
                            "dado sensível vai junto. Tirar a coluna do grant e servir por "
                            "função que confere o papel.")

    # 3 e 4. Policies: escrita que só confere autoria, e storage para anon que depende de RLS.
    policies_por_tabela: dict[str, list[dict]] = {}
    for p in banco.get("policies", []):
        policies_por_tabela.setdefault(p["tabela"], []).append(p)
    policies_finais = {(p["arquivo"], p["linha"]) for p in banco.get("policies", [])}
    for nome_arq, texto in limpos:
        linha_de = _mapa_linhas(texto)
        for m in RE_POLICY.finditer(texto):
            # Só a policy que sobreviveu até o fim das migrations (sem drop depois).
            if (nome_arq, linha_de(m.start())) not in policies_finais:
                continue
            trecho = _statement(texto, m.start())
            resto = trecho[m.end() - m.start():]
            nome, tabela = _nome_e_tabela(m)
            comando = _comando_da_policy(resto)
            papeis = _roles_da_policy(resto)
            expr = _expressao_apos(resto, r"with\s+check")
            if expr is None and comando in ("update", "all"):
                expr = _expressao_apos(resto, r"\busing")
            t = tabelas.get(tabela)
            if comando in ("insert", "update", "all") and expr is not None and t:
                expr = RE_UID_EMBRULHADO.sub("auth.uid()", re.sub(r"\s+", " ", expr)).lower()
                autoria = None
                for d in _disjuncoes(expr):
                    autoria = (re.fullmatch(r"(?:\w+\.)?\"?(\w+)\"? ?= ?auth\.uid\(\)", d)
                               or re.fullmatch(r"auth\.uid\(\) ?= ?(?:\w+\.)?\"?(\w+)\"?", d))
                    if autoria:
                        break
                if autoria:
                    col = autoria.group(1)
                    outras = sorted({c for c, _, _ in t["fks"] if c != col})
                    if outras:
                        add("escrita-so-confere-autoria", "medio",
                            f"Policy `{nome}` em `{tabela}` só confere autoria (`{col} = auth.uid()`)",
                            nome_arq, linha_de(m.start()),
                            detalhe=f"A linha aponta para {', '.join('`' + c + '`' for c in outras)}, "
                                    "e a checagem de escrita (ou um dos lados do OR dela) não confere "
                                    "se quem grava tem acesso a esse alvo. Basta ser o autor para "
                                    "gravar contra recurso de outro escopo. Em UPDATE e ALL sem WITH "
                                    "CHECK, o Postgres usa o USING como checagem, então ele entra na conta.")
            eh_storage = re.search(r"\bon\s+\"?storage\"?\s*\.\s*\"?objects\b", trecho, re.I)
            if eh_storage and comando in ("select", "all") and _alcanca_anon(papeis):
                cegas = sorted({
                    x.lower() for x in re.findall(r"\bfrom\s+" + SQ + r"([a-z0-9_]+)", trecho, re.I)
                    if x.lower() in rls_on and not any(
                        p["comando"] in ("select", "all") and _alcanca_anon(p["para"])
                        for p in policies_por_tabela.get(x.lower(), []))})
                if cegas:
                    add("storage-anon-inerte", "medio",
                        f"Policy `{nome}` em storage para visitante depende de `{', '.join(cegas)}`, "
                        "que o visitante não lê",
                        nome_arq, linha_de(m.start()),
                        detalhe="O subselect roda sob a RLS do visitante, e nenhuma policy de "
                                "leitura daquela tabela alcança anon: a policy de storage nunca "
                                "libera nada. Ou o download funciona por outro caminho que ninguém "
                                "documentou. Conferir como o arquivo chega de verdade.")

    # 5. Papel concedido no cadastro sem e-mail confirmado.
    for nome_arq, texto in limpos:
        linha_de = _mapa_linhas(texto)
        for m in RE_TRIGGER.finditer(texto):
            trecho = _statement(texto, m.start())
            if not re.search(r"\binsert\b[^;]*\bon\s+\"?auth\"?\s*\.\s*\"?users\b", trecho, re.I):
                continue
            alvo = re.search(r"execute\s+(?:function|procedure)\s+" + SQ + r"([a-z0-9_]+)", trecho, re.I)
            f = funcoes.get(alvo.group(1).lower()) if alvo else None
            if f and RE_CONVITE.search(f["corpo"]) and not re.search(r"confirmed_at", f["corpo"], re.I):
                add("papel-no-cadastro-sem-confirmacao", "alto",
                    f"Trigger `{m.group(1)}` dá papel no cadastro via `{alvo.group(1)}` sem exigir "
                    "e-mail confirmado",
                    nome_arq, linha_de(m.start()),
                    detalhe="O papel do convite é concedido no INSERT em auth.users. Com a "
                            "confirmação de e-mail desligada, quem souber o e-mail convidado cria "
                            "a conta e herda o papel. Com ela ligada, `email_confirmed_at` ainda é "
                            "nulo no INSERT: conceder num trigger AFTER UPDATE OF "
                            "email_confirmed_at, quando ele deixar de ser nulo.")

    # 6. Oráculo de convite: função com poder elevado que responde a visitante se um e-mail tem convite.
    for nome, f in sorted(funcoes.items()):
        if (f["definer"] and "email" in f["params"] and not fechada_pra_visitante(nome)
                and (RE_CONVITE.search(nome) or RE_CONVITE.search(f["corpo"]))):
            add("oraculo-de-convite", "medio",
                f"Função `{nome}` responde a visitante se um e-mail tem convite",
                f["arquivo"], f["linha"],
                detalhe="É SECURITY DEFINER, recebe e-mail e não foi revogada de public e anon. No "
                        "Supabase isso basta para virar RPC chamável sem login, mesmo sem GRANT "
                        "explícito. Qualquer visitante descobre quais e-mails têm convite pendente, "
                        "que é exatamente a lista de quem vale a pena tentar cadastrar primeiro.")

    # 7. Regra de "primeiro usuário vira dono" que pode voltar a valer.
    re_vazio = [
        re.compile(r"not\s+exists\s*\(\s*select\s+[^()]*?\bfrom\s+" + SQ + r"[a-z0-9_]+\"?\s*\)", re.I),
        re.compile(r"\(\s*select\s+count\s*\(\s*\*\s*\)\s+from\s+" + SQ + r"[a-z0-9_]+\"?\s*\)\s*=\s*0", re.I),
        re.compile(r"count\s*\(\s*\*\s*\)\s+into\s+(\w+)\s+from\s+" + SQ + r"[a-z0-9_]+\"?\s*;"
                   r"[\s\S]*?\bif\s+\1\s*=\s*0", re.I),
    ]
    for nome, f in sorted(funcoes.items()):
        if any(r.search(f["corpo"]) for r in re_vazio) and re.search(r"'(owner|dono|admin)'", f["corpo"], re.I):
            add("primeiro-usuario-vira-dono", "medio",
                f"Função `{nome}` dá papel de dono quando a tabela está vazia",
                f["arquivo"], f["linha"],
                detalhe="A porta fecha quando existe o primeiro perfil, e reabre se a tabela "
                        "esvaziar (um cascade de auth.users basta). Trocar por uma marca "
                        "permanente de instalação feita, que nunca volta a ser falsa.")

    # 8. SECURITY DEFINER sem REVOKE EXECUTE de public E anon.
    for f in banco.get("funcoes", []):
        nome = f["nome"]
        info = funcoes.get(nome, {})
        if not f.get("definer") or info.get("trigger") or fechada_pra_visitante(nome):
            continue
        # GRANT explícito a quem é de fora é intenção de expor: sobe pra alto, porque aí a
        # função precisa conferir por dentro quem chama, e o achado é conferir se confere.
        de_fora_explicito = sorted(explicito.get(nome, set()))
        add("definer-sem-revoke", "alto" if de_fora_explicito else "medio",
            f"Função definer `{nome}` sem REVOKE EXECUTE de public e anon"
            + (f" (GRANT explícito a {', '.join(de_fora_explicito)})" if de_fora_explicito else ""),
            info.get("arquivo", "?"), info.get("linha"),
            detalhe="Postgres concede EXECUTE a PUBLIC por padrão, e o Supabase concede também a "
                    "anon e authenticated por default privileges. Revogar só de um dos dois deixa "
                    "o outro caminho aberto. Se a função não é pra visitante: `revoke execute on "
                    "function ... from public, anon` no mesmo arquivo que a cria. Limite: revoke "
                    "por schema inteiro (`on all functions in schema`) não é reconhecido aqui.")

    # 9. Enum que cresceu, com comparação negativa sobre coluna daquele enum. Só vale a
    # comparação escrita ANTES de o enum crescer (quem escreveu depois já conhecia o valor
    # novo), ainda em vigor (função redefinida depois não conta) e cuja tabela na consulta
    # tem mesmo a coluna daquele enum (duas tabelas com `status` de enums diferentes é comum).
    defs_funcao = []
    for i, (_, texto) in enumerate(limpos):
        for m in RE_FUNC.finditer(texto):
            corpo = _corpo_da_funcao(texto, m.start())
            defs_funcao.append((m.group(1).lower(), i, m.start(), m.start() + len(corpo)))
    ultima_def: dict[str, tuple[int, int]] = {}
    for nome, i, ini, _ in defs_funcao:
        ultima_def[nome] = max(ultima_def.get(nome, (-1, -1)), (i, ini))
    crescimento: dict[str, tuple[int, int]] = {}
    for i, (_, texto) in enumerate(limpos):
        for m in RE_ADD_VALUE.finditer(texto):
            e = m.group(1).lower()
            crescimento[e] = max(crescimento.get(e, (-1, -1)), (i, m.start()))
    re_origem = re.compile(
        r"\b(?:from|join|update)\s+" + SQ + r"([a-z0-9_]+)\"?"
        r"(?:\s+(?:as\s+)?(?!(?:where|on|join|set|left|right|inner|full|cross|group|order|limit|using)\b)"
        r"([a-z_][a-z0-9_]*))?", re.I)
    for enum in sorted(crescimento):
        valores = set(banco.get("enums", {}).get(enum, []))
        tipo = re.compile(rf"^\"?(\w+)\"?\s+{SQ}{enum}\"?(?:\s|$|\[)", re.I)
        colunas_do_enum = {(tn, mm.group(1).lower()) for tn, t in tabelas.items()
                           for p in t["colunas"].values() if (mm := tipo.match(p))}
        if not colunas_do_enum or not valores:
            continue
        alt = "|".join(sorted({c for _, c in colunas_do_enum}))
        re_neg = re.compile(
            rf"(?:\b(\w+)\.)?\"?\b({alt})\"?\s*(?:<>|!=)\s*'([^']+)'"
            rf"|(?:\b(\w+)\.)?\"?\b({alt})\"?\s+not\s+in\s*\(([^)]*)\)", re.I)
        for i, (nome_arq, texto) in enumerate(limpos):
            linha_de = _mapa_linhas(texto)
            for m in re_neg.finditer(texto):
                if (i, m.start()) > crescimento[enum]:
                    continue
                dono = [d for d in defs_funcao if d[1] == i and d[2] <= m.start() < d[3]]
                if dono and ultima_def[dono[-1][0]] != (i, dono[-1][2]):
                    continue
                negacao_simples = m.group(3) is not None
                qual = (m.group(1) or m.group(4) or "").lower()
                col = (m.group(2) or m.group(5)).lower()
                lit = m.group(3) if negacao_simples else m.group(6).strip()
                literais = [lit] if negacao_simples else re.findall(r"'([^']+)'", lit)
                if not any(x in valores for x in literais):
                    continue
                trecho = texto[texto.rfind(";", 0, m.start()) + 1:m.start()]
                apelido: dict[str, str] = {}
                for o in re_origem.finditer(trecho):
                    apelido[o.group(1).lower()] = o.group(1).lower()
                    if o.group(2):
                        apelido[o.group(2).lower()] = o.group(1).lower()
                candidatas = {apelido[qual]} if qual in apelido else set(apelido.values())
                tabs = sorted(tn for tn in candidatas if (tn, col) in colunas_do_enum)
                if not tabs:
                    continue
                expr = f"{tabs[0]}.{col} <> '{lit}'" if negacao_simples else f"{tabs[0]}.{col} not in ({lit})"
                add("enum-cresceu-comparacao-negativa", "medio",
                    f"`{expr}` foi escrita antes de o enum `{enum}` ganhar valor novo",
                    nome_arq, linha_de(m.start()), dimensao="corretude",
                    detalhe="`<> 'x'` e `not in (...)` passam a incluir todo valor que o enum "
                            "ganhar depois, e esta comparação é anterior ao último valor novo e "
                            "continua em vigor. Um contador de abertos passa a contar pausado ou "
                            "cancelado. Trocar por lista positiva do que conta.")

    # 10. Intervalo de tempo sem CHECK de ordem (inline na coluna, na tabela ou por alter table).
    for tabela, t in sorted(tabelas.items()):
        for a, b in PARES_INTERVALO:
            if a not in t["colunas"] or b not in t["colunas"]:
                continue
            if not any(re.search(rf"\b{a}\b", c, re.I) and re.search(rf"\b{b}\b", c, re.I) for c in t["checks"]):
                add("intervalo-sem-check", "medio",
                    f"`{tabela}` tem `{a}` e `{b}` sem CHECK de ordem",
                    t.get("arquivo", "?"), t.get("linha"), dimensao="corretude",
                    detalhe=f"Nada impede gravar `{b}` antes de `{a}`: a duração sai negativa e "
                            "desconta ou infla qualquer saldo que some esse intervalo. "
                            f"`check ({b} is null or {b} >= {a})`.")

    # 11. FK em cascata que apaga histórico financeiro ou de horas.
    for tabela, t in sorted(tabelas.items()):
        tokens = set(tabela.split("_"))
        if not (tokens & TOKENS_HISTORICO) or (tokens & TOKENS_NAO_HISTORICO):
            continue
        for col, ref, on_delete in sorted(set(t["fks"])):
            if on_delete == "cascade" and ref not in RAIZES_DE_INQUILINO:
                add("cascade-apaga-historico", "medio",
                    f"`{tabela}.{col}` apaga o histórico junto com `{ref}` (on delete cascade)",
                    t.get("arquivo", "?"), t.get("linha"), dimensao="corretude",
                    detalhe="Apagar o registro pai some com as linhas de histórico, e o saldo já "
                            "mostrado ao cliente muda sem rastro. Usar `restrict` e arquivar o pai, "
                            "ou copiar o histórico antes.")

    # 12. Documentação que cita policy que não existe.
    # Conhecido = aparece em algum lugar do SQL (tabela, coluna, função, trigger, índice,
    # extensão) ou é papel do banco. O que sobra é nome que a instalação limpa não cria.
    conhecidos = PAPEIS_DO_BANCO | {x for _, t in limpos for x in re.findall(r"[a-z_][a-z0-9_]*", t.lower())}
    for arq in coletar(perfil, "docs"):
        for n, linha in enumerate(ler(arq).splitlines(), 1):
            if not re.search(r"polic", linha, re.I):
                continue
            for tok in re.findall(r"`([a-z0-9_]+)`", linha):
                if "_" in tok and tok not in conhecidos:
                    add("doc-cita-policy-inexistente", "medio",
                        f"Documentação cita a policy `{tok}`, que não existe nas migrations",
                        rel(perfil, arq), n,
                        detalhe="A instalação limpa não cria o que o manual promete. Ou a policy "
                                "foi aplicada à mão em produção (repo e banco divergiram), ou o "
                                "manual descreve proteção que não existe.")

    # 13. Arquivo reaplicado (baseline, seed) que concede a quem é de fora e só revoga depois.
    # Migration roda uma vez, dentro de transação; arquivo reaplicado com o app no ar roda
    # comando a comando, e entre o GRANT e o REVOKE a função ou tabela fica aberta. O estado
    # final está certo, e é por isso que quem calcula só o estado final nunca acusa.
    de_fora = {"anon", "authenticated", "public"}
    for arq in coletar(perfil, "reaplicados"):
        texto = _sem_comentario(ler(arq))
        linha_de = _mapa_linhas(texto)
        # Eventos por (objeto, papel), em ordem. Só é janela se o estado FINAL do papel no
        # arquivo for revogado: `revoke ... from public, anon, authenticated` seguido de
        # `grant ... to authenticated` é o idioma de quem QUER o acesso, não janela.
        eventos: dict[tuple[str, str], list[tuple[str, int]]] = {}
        for m in RE_GRANT_OU_REVOKE.finditer(texto):
            st = _statement(texto, m.start())
            alvo = RE_ALVO_FUNCAO.search(st) or re.search(
                r"\bon\s+(?:table\s+)?" + SQ + r"([a-z0-9_]+)", st, re.I)
            if not alvo:
                continue
            nome = alvo.group(1).lower()
            if m.group(1).lower() == "grant":
                # Tabela com RLS já ligada neste ponto do arquivo não abre janela: quem barra
                # durante a reaplicação é a policy, não o grant.
                if not RE_ALVO_FUNCAO.search(st) and re.search(
                        r"alter\s+table\s+(?:only\s+)?" + SQ + re.escape(nome)
                        + r"\"?\s+enable\s+row\s+level\s+security", texto[:m.start()], re.I):
                    continue
                for papel in _papeis_do_comando(st, "to") & de_fora:
                    eventos.setdefault((nome, papel), []).append(("grant", m.start()))
            else:
                for papel in _papeis_do_comando(st, "from") & de_fora:
                    eventos.setdefault((nome, papel), []).append(("revoke", m.start()))
        acusados: set[str] = set()
        for (nome, papel), evs in sorted(eventos.items()):
            concedido = next((pos for tipo, pos in evs if tipo == "grant"), None)
            if concedido is None or evs[-1][0] != "revoke" or nome in acusados:
                continue
            acusados.add(nome)
            fim = evs[-1][1]
            add("janela-na-reaplicacao", "medio",
                f"`{nome}` é concedido a {papel} e só revogado {linha_de(fim) - linha_de(concedido)} linhas depois",
                rel(perfil, arq), linha_de(concedido),
                detalhe="Este arquivo é reaplicado inteiro, comando a comando, com o app no "
                        "ar. Entre o GRANT e o REVOKE o objeto fica aberto a quem é de fora, e "
                        "o estado final revogado mostra que o acesso não era pra existir. "
                        "Auditoria que só olha o estado final não vê. Tirar a concessão do "
                        "corpo ou mover o REVOKE pra antes, e rodar o arquivo numa transação só.")


# ---------------------------------------------------------------------------
# HAR — a camada de EXECUÇÃO
# ---------------------------------------------------------------------------

CABECALHOS_SENSIVEIS = {"authorization", "cookie", "set-cookie", "x-api-key", "apikey"}
CAMPOS_PII = ["cpf", "cnpj", "senha", "password", "token", "nascimento", "rg", "passaporte",
              "telefone", "endereco", "cep", "email", "e_mail", "ssn"]


def mascarar(valor: str) -> str:
    v = str(valor)
    if len(v) <= 10:
        return "***"
    return f"{v[:4]}...{v[-4:]} ({len(v)} chars)"


def analisar_har(caminho: Path) -> dict:
    """Lê o HAR e responde o que código não responde: o que o servidor SERVIU.

    NUNCA grava valor de token, cookie ou PII: só o tipo, o campo e o tamanho.
    """
    dados = json.loads(caminho.read_text(encoding="utf-8", errors="replace"))
    entradas = dados.get("log", {}).get("entries", [])
    achados: list[dict] = []
    hosts: dict[str, int] = {}
    sem_hsts: set[str] = set()
    resumo_headers: dict[str, set[str]] = {}

    for e in entradas:
        req = e.get("request", {})
        res = e.get("response", {})
        url = req.get("url", "")
        host = re.sub(r"^https?://([^/]+).*$", r"\1", url)
        hosts[host] = hosts.get(host, 0) + 1
        rh = {h.get("name", "").lower(): h.get("value", "") for h in res.get("headers", [])}
        for nome in rh:
            resumo_headers.setdefault(nome, set()).add(host)

        if url.startswith("http://"):
            achados.append({"regra": "har-http-puro", "severidade": "alto",
                            "titulo": f"Requisição em HTTP puro para {host}",
                            "detalhe": "Tráfego sem TLS: dá pra ler e alterar no caminho."})

        if "?" in url:
            qs = url.split("?", 1)[1].lower()
            for campo in ("token", "senha", "password", "cpf", "access_token", "apikey"):
                if f"{campo}=" in qs:
                    achados.append({
                        "regra": "har-segredo-na-url", "severidade": "alto",
                        "titulo": f"`{campo}` na query string de {host}",
                        "detalhe": "Query string cai em log de servidor, histórico do navegador e "
                                   "cabeçalho Referer. Mover pro corpo do POST."})

        for h in res.get("headers", []):
            if h.get("name", "").lower() != "set-cookie":
                continue
            v = h.get("value", "")
            falta = [f for f in ("HttpOnly", "Secure", "SameSite") if f.lower() not in v.lower()]
            if falta:
                nome_cookie = v.split("=", 1)[0]
                achados.append({
                    "regra": "har-cookie-sem-flag", "severidade": "alto",
                    "titulo": f"Cookie `{nome_cookie}` sem {', '.join(falta)}",
                    "detalhe": "HttpOnly impede JS de ler (defesa contra XSS); Secure exige HTTPS; "
                               "SameSite reduz CSRF."})

        if rh.get("access-control-allow-origin") == "*" and \
                rh.get("access-control-allow-credentials", "").lower() == "true":
            achados.append({"regra": "har-cors-curinga", "severidade": "critico",
                            "titulo": f"CORS `*` com credentials:true em {host}",
                            "detalhe": "Qualquer site lê a resposta autenticada."})

        req_headers = {h.get("name", "").lower() for h in req.get("headers", [])}
        autenticada = bool(req_headers & CABECALHOS_SENSIVEIS)
        cache = rh.get("cache-control", "").lower()
        if autenticada and cache and not any(
                d in cache for d in ("no-store", "no-cache", "private", "max-age=0")):
            achados.append({"regra": "har-cache-autenticado", "severidade": "medio",
                            "titulo": f"Resposta autenticada cacheável em {host}",
                            "detalhe": f"Cache-Control: {cache}. Dado de um usuário pode ser "
                                       "servido a outro por cache intermediário."})

        if url.startswith("https://") and "strict-transport-security" not in rh:
            sem_hsts.add(host)

        corpo = res.get("content", {}).get("text") or ""
        if corpo and len(corpo) < 400_000:
            baixo = corpo.lower()
            campos = sorted({c for c in CAMPOS_PII if f'"{c}"' in baixo})
            if campos:
                achados.append({
                    "regra": "har-overfetch-pii", "severidade": "medio",
                    "titulo": f"Resposta de {host} traz campo pessoal: {', '.join(campos)}",
                    "detalhe": "A tela mostrar pouco não prova que a resposta trouxe pouco. "
                               "Confirmar se cada campo é usado; se não, cortar no servidor. "
                               "Endpoint: " + url.split("?")[0]})

    for host in sorted(sem_hsts):
        achados.append({"regra": "har-sem-hsts", "severidade": "medio",
                        "titulo": f"Sem Strict-Transport-Security em {host}",
                        "detalhe": "Permite tentativa de downgrade pra HTTP."})

    vistos, unicos = set(), []
    for a in achados:
        k = (a["regra"], a["titulo"])
        if k in vistos:
            continue
        vistos.add(k)
        a["dimensao"] = "seguranca"
        a["origem"] = "har"
        a["arquivo"] = "HAR (execução)"
        unicos.append(a)

    return {
        "arquivo_har": caminho.name,
        "requisicoes": len(entradas),
        "hosts": dict(sorted(hosts.items(), key=lambda kv: -kv[1])),
        "headers_vistos": {k: sorted(v) for k, v in sorted(resumo_headers.items())},
        "achados": unicos,
    }


# ---------------------------------------------------------------------------
# PARTIÇÃO — a prova de cobertura
# ---------------------------------------------------------------------------

def particionar(itens: list[str], tamanho: int, prefixo: str) -> list[dict]:
    """Fatia ordenado e determinístico. A lista de cada lote é EXPLÍCITA."""
    itens = sorted(set(itens))
    lotes = []
    for i in range(0, len(itens), tamanho):
        pedaco = itens[i:i + tamanho]
        lotes.append({
            "id": f"{prefixo}-{len(lotes) + 1:02d}",
            "tipo": prefixo,
            "itens": pedaco,
            "qtd": len(pedaco),
        })
    return lotes


def provar_cobertura(lotes: list[dict], universo: list[str], rotulo: str) -> dict:
    """Aritmética, não promessa. Soma bate e interseção é vazia, ou levanta erro."""
    universo_set = set(universo)
    soma = sum(l["qtd"] for l in lotes)
    uniao: set[str] = set()
    sobreposicao: set[str] = set()
    for l in lotes:
        s = set(l["itens"])
        sobreposicao |= (uniao & s)
        uniao |= s
    faltando = sorted(universo_set - uniao)
    sobrando = sorted(uniao - universo_set)
    ok = (soma == len(universo_set) == len(uniao)
          and not sobreposicao and not faltando and not sobrando)
    prova = {
        "rotulo": rotulo, "universo": len(universo_set), "soma_dos_lotes": soma,
        "itens_unicos_cobertos": len(uniao), "sobreposicao": sorted(sobreposicao),
        "faltando": faltando, "sobrando": sobrando, "ok": ok,
    }
    if not ok:
        raise AssertionError(f"COBERTURA QUEBRADA em {rotulo}: {json.dumps(prova, ensure_ascii=False)}")
    return prova


def montar_manifesto(perfil: dict, banco: dict, codigo: dict, modo: str,
                     dimensao: str | None) -> dict:
    tabelas = sorted(banco["tabelas"].keys())
    serverfns = sorted(s["id"] for s in codigo["server_functions"])
    rotas = sorted(r["id"] for r in codigo["rotas_api"])

    dinheiro_decl = set(perfil.get("tabelas", {}).get("dinheiro", []))
    tabelas_dinheiro = sorted(dinheiro_decl & set(tabelas))
    tabelas_normais = [t for t in tabelas if t not in dinheiro_decl]

    lotes: list[dict] = []
    provas: list[dict] = []

    lt = particionar(tabelas_normais, LOTE_TABELAS, "tabelas")
    for l in lt:
        l["dimensoes"] = ["seguranca"]
        l["executor"] = "subagente"
    provas.append(provar_cobertura(lt, tabelas_normais, "tabelas (fora do dinheiro)"))
    lotes += lt

    lf = particionar(serverfns, LOTE_SERVERFN, "serverfn")
    for l in lf:
        l["dimensoes"] = ["seguranca", "corretude"]
        l["executor"] = "subagente"
    provas.append(provar_cobertura(lf, serverfns, "server functions"))
    lotes += lf

    lr = particionar(rotas, LOTE_ROTAS_API, "rotas")
    for l in lr:
        l["dimensoes"] = ["seguranca"]
        l["executor"] = "subagente"
    provas.append(provar_cobertura(lr, rotas, "rotas de API"))
    lotes += lr

    if tabelas_dinheiro:
        lotes.append({
            "id": "dinheiro-01", "tipo": "dinheiro", "itens": tabelas_dinheiro,
            "qtd": len(tabelas_dinheiro), "dimensoes": ["seguranca", "corretude"],
            "executor": "orquestrador",
            "nota": "Não delegar: é onde o erro custa direto.",
        })

    tipos = [t.get("id") for t in perfil.get("tipos_de_acesso", [])]
    if tipos:
        lotes.append({
            "id": "matriz-01", "tipo": "matriz_acesso", "itens": tipos,
            "qtd": len(tipos), "dimensoes": ["corretude"], "executor": "orquestrador",
            "nota": "NÃO PARTICIONAR: o bug mora no cruzamento entre guarda e tipo de acesso. "
                    "Fatiar a matriz esconde justamente o que ela existe pra achar.",
        })

    if modo == "leve":
        lotes = [l for l in lotes if l["tipo"] in ("dinheiro", "matriz_acesso")]
    if dimensao:
        lotes = [l for l in lotes if dimensao in l["dimensoes"]]

    return {"lotes": lotes, "provas_de_cobertura": provas, "total_lotes": len(lotes),
            "tabelas_dinheiro": tabelas_dinheiro}


# ---------------------------------------------------------------------------
# ORQUESTRAÇÃO DO SCANNER
# ---------------------------------------------------------------------------

def id_estavel(regra: str, arquivo: str, simbolo: str = "") -> str:
    base = f"{regra}|{arquivo}|{simbolo}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()[:10]


def resolver_saida(arg: Path | None) -> Path:
    if arg:
        return arg.resolve()
    env = os.environ.get("SAAS_AUDIT_SAIDA")
    if env:
        return Path(env).expanduser().resolve()
    return SAIDA_PADRAO


def _dentro_de(filho: Path, pai: Path) -> bool:
    try:
        filho.relative_to(pai)
        return True
    except ValueError:
        return False


def escanear(perfil_path: Path, modo: str, dimensao: str | None,
             har: Path | None, saida_base: Path) -> dict:
    perfil = carregar_perfil(perfil_path)
    nome_app = perfil["app"]["nome"]

    if _dentro_de(saida_base, perfil["_raiz"]):
        eprint(f"[scanner] AVISO: a pasta de saída ({saida_base}) está DENTRO do repositório "
               "auditado. Relatório de vulnerabilidade a um `git add .` de ir pro remoto. "
               "Use --saida ou SAAS_AUDIT_SAIDA apontando pra fora, ou garanta o .gitignore.")

    ok_b, banco = run_safe("banco", inventario_banco, perfil)
    ok_c, codigo = run_safe("codigo", inventario_codigo, perfil)
    banco = banco or {"tabelas": {}, "funcoes": [], "tabelas_sem_rls": [],
                      "tabelas_com_rls_sem_policy": [], "policies_tautologicas": [],
                      "escrita_sem_with_check": [], "definer_sem_searchpath": [],
                      "views_definer": [], "grants_para_anon": [], "policies_empilhadas": []}
    codigo = codigo or {"server_functions": [], "rotas_api": [], "rpcs_chamadas": [],
                        "privilegio_fora_do_permitido": [], "testes": [], "total_testes": 0}
    ok_m, mec = run_safe("mecanicos", detectores_mecanicos, perfil, banco, codigo)
    mec = mec or {"achados": [], "front_hits": []}

    dados_har = None
    if har:
        ok_h, dados_har = run_safe("har", analisar_har, har)
        if dados_har:
            mec["achados"] += dados_har["achados"]

    manifesto = montar_manifesto(perfil, banco, codigo, modo, dimensao)

    for a in mec["achados"]:
        a["id_estavel"] = id_estavel(a["regra"], a.get("arquivo", ""), a.get("titulo", ""))

    agora = datetime.now(timezone.utc).astimezone()
    pasta = saida_base / nome_app / f"{agora:%Y-%m-%d}-{modo}"
    for sub in ("lotes", "ceticos", "ground-truth", "har"):
        (pasta / sub).mkdir(parents=True, exist_ok=True)

    run = {
        "app": nome_app,
        "titulo": perfil["app"].get("titulo", nome_app),
        "modo": modo,
        "dimensao_filtrada": dimensao,
        "iniciado_em": agora.isoformat(timespec="seconds"),
        "perfil": str(perfil_path),
        "perfil_hash": perfil["_hash"],
        "raiz_auditada": str(perfil["_raiz"]),
        "detectores_ok": {"banco": ok_b, "codigo": ok_c, "mecanicos": ok_m},
        "har_usado": har.name if har else None,
        "fases_aprovadas": [],
        **manifesto,
    }

    (pasta / "run.json").write_text(
        json.dumps(run, ensure_ascii=False, indent=2), encoding="utf-8")
    (pasta / "inventario.json").write_text(
        json.dumps({"banco": banco, "codigo": codigo}, ensure_ascii=False, indent=2),
        encoding="utf-8")
    (pasta / "mecanicos.json").write_text(
        json.dumps(mec, ensure_ascii=False, indent=2), encoding="utf-8")
    if dados_har:
        (pasta / "har" / "analise.json").write_text(
            json.dumps(dados_har, ensure_ascii=False, indent=2), encoding="utf-8")

    return {"pasta": pasta, "run": run, "banco": banco, "codigo": codigo,
            "mecanicos": mec, "har": dados_har, "perfil": perfil}


def resumo(res: dict) -> str:
    b, c, m, run = res["banco"], res["codigo"], res["mecanicos"], res["run"]
    L = []
    L.append(f"SAAS-SECURITY-AUDIT :: {run['titulo']} :: modo {run['modo']}")
    L.append(f"pasta: {res['pasta']}")
    L.append("")
    L.append("INVENTÁRIO (medido)")
    L.append(f"  migrations ................ {b.get('arquivos_migration', 0)}")
    L.append(f"  tabelas ................... {b.get('total_tabelas', 0)}")
    L.append(f"  RLS habilitado ............ {b.get('total_rls', 0)}")
    L.append(f"  policies .................. {b.get('total_policies', 0)}")
    L.append(f"  funções SQL ............... {b.get('total_funcoes', 0)}")
    L.append(f"  SECURITY DEFINER .......... {b.get('total_definer', 0)}"
             f"  (sem search_path: {len(b.get('definer_sem_searchpath', []))})")
    L.append(f"  triggers .................. {b.get('total_triggers', 0)}")
    L.append(f"  server functions .......... {c.get('total_server_functions', 0)}"
             f"  em {c.get('arquivos_server_functions', 0)} arquivos")
    L.append(f"  rotas de API .............. {c.get('total_rotas_api', 0)}")
    L.append(f"  sítios de service_role .... {c.get('total_sitios_privilegiado', 0)}"
             f"  (fora do permitido: {len(c.get('privilegio_fora_do_permitido', []))})")
    L.append(f"  testes .................... {c.get('total_testes', 0)}")
    if res["har"]:
        L.append(f"  HAR: {res['har']['requisicoes']} requisições, "
                 f"{len(res['har']['hosts'])} hosts")
    L.append("")
    L.append("ACHADOS MECÂNICOS (não precisam de julgamento)")
    por_sev: dict[str, int] = {}
    for a in m["achados"]:
        por_sev[a["severidade"]] = por_sev.get(a["severidade"], 0) + 1
    for sev in ("critico", "alto", "medio", "baixo", "info"):
        if por_sev.get(sev):
            L.append(f"  {sev:<8} {por_sev[sev]}")
    if not m["achados"]:
        L.append("  nenhum")
    else:
        L.append("")
        for a in sorted(m["achados"],
                        key=lambda x: ("critico alto medio baixo info".split()
                                       .index(x["severidade"]))):
            loc = a.get("arquivo", "?")
            if a.get("linha"):
                loc += f":{a['linha']}"
            L.append(f"  [{a['severidade'][:4]}] {a['titulo']}")
            L.append(f"         {loc}")
    L.append("")
    L.append("PROVA DE COBERTURA (aritmética, não promessa)")
    for p in run["provas_de_cobertura"]:
        marca = "OK " if p["ok"] else "FALHOU"
        L.append(f"  {marca} {p['rotulo']}: universo {p['universo']} == "
                 f"soma {p['soma_dos_lotes']}, sobreposição {len(p['sobreposicao'])}")
    L.append("")
    L.append(f"MANIFESTO: {run['total_lotes']} lotes")
    for l in run["lotes"]:
        quem = "ORQUESTRADOR" if l["executor"] == "orquestrador" else "agente"
        L.append(f"  {l['id']:<12} {l['qtd']:>3} itens  "
                 f"[{'+'.join(d[:3] for d in l['dimensoes'])}]  {quem}")
    return "\n".join(L)


def descobrir(raiz: Path) -> str:
    """Rascunho de perfil pra app novo. O humano revisa antes de usar."""
    def busca(padrao, limite=6):
        return [p for p in raiz.rglob(padrao)
                if not ({"node_modules", ".git", "dist", ".next", ".vercel"} & set(p.parts))][:limite]

    achados = {
        "migrations": busca("*.sql"),
        "server_functions (createServerFn / use server / Edge)": busca("*.functions.ts")
            + busca("*.server.ts") + busca("actions.ts") + busca("index.ts"),
        "rotas_api": busca("api.*.ts") + busca("route.ts"),
        "config_deploy": busca("vercel.json") + busca("netlify.toml") + busca("wrangler.toml"),
        "testes": busca("*.test.ts") + busca("*.spec.ts"),
    }
    L = [f"# rascunho de perfil pra {raiz.name}: REVISAR ANTES DE USAR", ""]
    for k, v in achados.items():
        L.append(f"# {k}: {len(v)} exemplo(s)")
        for p in v:
            L.append(f"#   {p.relative_to(raiz).as_posix()}")
    L.append("")
    L.append("# Copie referencias/perfil.template.toml para .claude/auditoria/perfil.toml no app")
    L.append("# e preencha [caminhos] com os globs acima.")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(description="Motor determinístico do saas-security-audit")
    ap.add_argument("--perfil", type=Path, help="caminho do perfil.toml do app")
    ap.add_argument("--modo", default="completa", choices=["completa", "leve"])
    ap.add_argument("--dimensao", default=None, choices=["seguranca", "corretude"])
    ap.add_argument("--har", type=Path, default=None, help="arquivo .har opcional")
    ap.add_argument("--saida", type=Path, default=None,
                    help="pasta base dos artefatos (padrão: ~/saas-security-audit/auditorias)")
    ap.add_argument("--descobrir", type=Path, default=None, help="raiz de app sem perfil")
    ap.add_argument("--print", dest="imprimir", action="store_true")
    args = ap.parse_args()

    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:
            pass

    if args.descobrir:
        print(descobrir(args.descobrir.resolve()))
        return

    if not args.perfil:
        ap.error("--perfil é obrigatório (ou use --descobrir)")
    if args.har and not args.har.is_file():
        ap.error(f"HAR não encontrado: {args.har}")

    res = escanear(args.perfil.resolve(), args.modo, args.dimensao,
                   args.har.resolve() if args.har else None,
                   resolver_saida(args.saida))
    if args.imprimir:
        print(resumo(res))
    else:
        print(f"Artefatos em: {res['pasta']}")
        print(f"{res['run']['total_lotes']} lotes no manifesto. "
              f"{len(res['mecanicos']['achados'])} achados mecânicos.")


if __name__ == "__main__":
    main()
