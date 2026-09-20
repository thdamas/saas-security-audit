"""
painel.py — painel HTML do saas-security-audit.

Lê os artefatos que o scanner e os agentes gravaram e emite UM HTML autocontido e local.
NÃO detecta nada: painel que reimplementa detecção diverge do motor com o tempo.

Duas decisões deliberadas:

1. GRÁFICO EM SVG/CSS PURO, sem biblioteca. A peça carrega achado de segurança e não deve
   fazer requisição a terceiro, e precisa abrir offline. Donut, barra, heatmap e matriz
   saem em SVG e grid sem dependência nenhuma.
2. ZERO REQUISIÇÃO EXTERNA. Fonte de sistema, nada de CDN. Um arquivo, abre em qualquer
   lugar, inclusive numa máquina sem internet.

Uso:
    python painel.py --pasta <saida>/<app>/AAAA-MM-DD-modo
    python painel.py --pasta <...> --abrir

Garantias:
    - Read-only sobre o app auditado.
    - Escreve só dentro da pasta da execução e em <saida>/_achados/ (baseline de status).
    - Nunca imprime valor de segredo: mascara qualquer coisa que pareça token.
    - Todo texto vai pro DOM por textContent, nunca innerHTML.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
import webbrowser
from datetime import datetime
from pathlib import Path

# Cor de acento do painel. Uma só, de propósito.
ACENTO = "#C4F02A"
SEVERIDADES = ["critico", "alto", "medio", "baixo", "info"]
COR_SEV = {
    "critico": "#FF4D3D",
    "alto": "#F5A623",
    "medio": "#FFD60A",
    "baixo": "#2D7DFF",
    "info": "#8A8A82",
}
ROTULO_SEV = {"critico": "Crítico", "alto": "Alto", "medio": "Médio",
              "baixo": "Baixo", "info": "Info"}
STATUS = ["Aberto", "Em correção", "Corrigido", "Aceito", "Falso-positivo"]

# Mascara qualquer coisa com cara de segredo antes de ir pro HTML.
PADROES_MASCARA = [
    re.compile(r"sk_live_[A-Za-z0-9]{6,}"), re.compile(r"sk_test_[A-Za-z0-9]{6,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"),
    re.compile(r"sk-ant-[A-Za-z0-9_-]{6,}"), re.compile(r"re_[A-Za-z0-9]{12,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(postgres(ql)?://[^\s:]+:)[^\s@]+(@)"),
]


def mascarar_texto(s):
    if not isinstance(s, str):
        return s
    for rx in PADROES_MASCARA:
        s = rx.sub(lambda m: (m.group(0)[:6] + "..." + m.group(0)[-4:]), s)
    return s


def limpar(obj):
    """Mascara recursivamente. Ultima linha de defesa antes do HTML."""
    if isinstance(obj, dict):
        return {k: limpar(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [limpar(v) for v in obj]
    return mascarar_texto(obj)


def ler_json(p: Path, default=None):
    if not p.is_file():
        return default
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except Exception as e:
        print(f"[painel] nao consegui ler {p.name}: {e}", file=sys.stderr)
        return default


# ---------------------------------------------------------------------------
# COLETA E RECONCILIACAO
# ---------------------------------------------------------------------------

def id_estavel(regra, arquivo, titulo):
    return hashlib.sha256(f"{regra}|{arquivo}|{titulo}".encode()).hexdigest()[:10]


def coletar(pasta: Path) -> dict:
    run = ler_json(pasta / "run.json", {}) or {}
    mecanicos = ler_json(pasta / "mecanicos.json", {"achados": []}) or {"achados": []}
    har = ler_json(pasta / "har" / "analise.json")
    leitura = ler_json(pasta / "leitura.json")
    inventario = ler_json(pasta / "inventario.json", {}) or {}

    achados: list[dict] = []

    # 1. Mecanicos (do scanner)
    for a in mecanicos.get("achados", []):
        achados.append({
            "id_estavel": a.get("id_estavel") or id_estavel(
                a.get("regra", ""), a.get("arquivo", ""), a.get("titulo", "")),
            "titulo": a.get("titulo", "sem titulo"),
            "severidade": a.get("severidade", "info"),
            "severidade_original": a.get("severidade", "info"),
            "dimensao": a.get("dimensao", "seguranca"),
            "categoria": a.get("regra", "mecanico"),
            "arquivo": a.get("arquivo", ""),
            "linha": a.get("linha"),
            "detalhe": a.get("detalhe", ""),
            "origem": a.get("origem", "mecanico"),
            "lote": "scanner",
            "veredito": None,
        })

    # 2. Lotes de agente
    lotes_lidos = []
    for arq in sorted((pasta / "lotes").glob("*.json")):
        if arq.name.startswith("_"):
            continue
        d = ler_json(arq)
        if not isinstance(d, dict):
            print(f"[painel] ignorando {arq.name}: nao e objeto de lote.", file=sys.stderr)
            continue
        lotes_lidos.append(arq.stem)
        for a in d.get("achados", []):
            sev = a.get("severidade", "info")
            achados.append({
                "id_estavel": id_estavel(a.get("categoria", ""), a.get("arquivo", ""),
                                         a.get("titulo", "")),
                "titulo": a.get("titulo", "sem titulo"),
                "severidade": sev,
                "severidade_original": sev,
                "dimensao": a.get("lente") and "corretude" or d.get("dimensao", "seguranca"),
                "lente": a.get("lente"),
                "categoria": a.get("categoria", "?"),
                "objeto": a.get("objeto", ""),
                "arquivo": a.get("arquivo", ""),
                "linha": a.get("linha"),
                "evidencia": a.get("evidencia", ""),
                "detalhe": a.get("o_que_e", ""),
                "por_que": a.get("por_que_perigoso") or a.get("impacto", ""),
                "cenario": a.get("cenario_de_exploracao") or a.get("cenario_real", ""),
                "causa_raiz": a.get("causa_raiz", ""),
                "correcao": a.get("correcao_proposta", ""),
                "teste": a.get("teste_de_validacao") or a.get("teste_de_regressao", ""),
                "confianca": a.get("confianca", "plausivel"),
                "por_que_confianca": a.get("por_que_essa_confianca", ""),
                "bloqueadores_procurados": a.get("bloqueadores_que_eu_procurei", []),
                "origem": "agente",
                "lote": d.get("lote", arq.stem),
                "veredito": None,
            })

    # 3. Vereditos do cetico. Aplicar e o passo que separa auditoria de teatro:
    #    refutado sai da conta de bloqueador, ajustado muda de severidade.
    vereditos = {}
    for arq in sorted((pasta / "ceticos").glob("*.json")):
        # Arquivo com `_` na frente e material de APOIO (a entrada que eu monto pro
        # cetico), nao resultado. Sem esta guarda o painel quebra ao encontrar uma
        # lista onde espera um objeto. Mesma convencao vale em lotes/.
        if arq.name.startswith("_"):
            continue
        d = ler_json(arq)
        if not isinstance(d, dict):
            print(f"[painel] ignorando {arq.name}: nao e objeto de veredito.", file=sys.stderr)
            continue
        for v in d.get("vereditos", []):
            vereditos[v.get("titulo_do_achado", "").strip()] = v

    for a in achados:
        v = vereditos.get(a["titulo"].strip())
        if not v:
            continue
        a["veredito"] = v.get("veredito")
        a["justificativa_cetico"] = v.get("justificativa", "")
        a["bloqueadores_cetico"] = v.get("bloqueadores_procurados", [])
        ver = (v.get("veredito") or "").strip().lower()
        if ver == "ajustado" and v.get("severidade_ajustada"):
            a["severidade"] = v["severidade_ajustada"]
        if ver == "refutado":
            a["severidade"] = "info"
            a["refutado"] = True
        # "refutado (não implantado)": o bloqueador existe no código, mas não na branch que
        # vai pra produção. O código está certo e a produção está errada, então o achado
        # CONTINUA contando como bloqueador. Só ganha a etiqueta.
        if ver.startswith("refutado") and ver != "refutado":
            a["nao_implantado"] = True

    # 4. Baseline: status dado em rodada anterior.
    #    Sem isto, "Aceito" morre com o localStorage e a rodada seguinte reabre tudo.
    app = run.get("app", "app")
    # <saida>/<app>/<rodada> -> <saida>/_achados/<app>.json
    base_path = pasta.parent.parent / "_achados" / f"{app}.json"
    baseline = ler_json(base_path, {}) or {}
    for a in achados:
        prev = baseline.get(a["id_estavel"])
        a["status"] = prev.get("status") if isinstance(prev, dict) else "Aberto"
        if isinstance(prev, dict) and prev.get("razao"):
            a["razao_baseline"] = prev["razao"]

    # 5. Dedupe por id estavel, agrupando localizacoes
    por_id: dict[str, dict] = {}
    for a in achados:
        k = a["id_estavel"]
        if k in por_id:
            loc = f"{a.get('arquivo','')}:{a.get('linha') or ''}".rstrip(":")
            por_id[k].setdefault("localizacoes_extra", [])
            if loc and loc not in por_id[k]["localizacoes_extra"]:
                por_id[k]["localizacoes_extra"].append(loc)
        else:
            por_id[k] = a

    ordem = {s: i for i, s in enumerate(SEVERIDADES)}
    finais = sorted(por_id.values(),
                    key=lambda x: (ordem.get(x["severidade"], 9), x["titulo"]))

    # IDs de exibicao, estaveis dentro da rodada
    cont = {"seguranca": 0, "corretude": 0}
    for a in finais:
        dim = a.get("dimensao", "seguranca")
        cont[dim] = cont.get(dim, 0) + 1
        a["id"] = f"{'SEC' if dim == 'seguranca' else 'COR'}-{cont[dim]:03d}"

    # A matriz de acesso (lente B1) nasce no lote `matriz-01`, feito pelo orquestrador.
    # Na v1 o painel a procurava em `leitura.matriz` e a secao 04 saia VAZIA, justo o
    # visual que mais entrega a dimensao B.
    matriz = None
    for nome in ("matriz-01", "matriz"):
        d = ler_json(pasta / "lotes" / f"{nome}.json")
        if isinstance(d, dict) and d.get("matriz"):
            matriz = d["matriz"]
            break

    return {"run": run, "achados": finais, "har": har, "leitura": leitura,
            "matriz": matriz, "inventario": inventario,
            "lotes_lidos": lotes_lidos, "baseline_path": base_path}


def gravar_baseline(dados: dict):
    """Persiste status em disco. localStorage sozinho nao atravessa execucao."""
    p: Path = dados["baseline_path"]
    p.parent.mkdir(parents=True, exist_ok=True)
    atual = ler_json(p, {}) or {}
    for a in dados["achados"]:
        entry = atual.get(a["id_estavel"], {})
        entry.setdefault("status", a.get("status", "Aberto"))
        entry["titulo"] = a["titulo"]
        entry["severidade"] = a["severidade"]
        entry["visto_em"] = datetime.now().strftime("%Y-%m-%d")
        atual[a["id_estavel"]] = entry
    p.write_text(json.dumps(atual, ensure_ascii=False, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# METRICAS
# ---------------------------------------------------------------------------

def metricas(dados: dict) -> dict:
    ach = dados["achados"]
    def conta(dim):
        d = {s: 0 for s in SEVERIDADES}
        for a in ach:
            if a.get("dimensao") == dim and not a.get("refutado"):
                d[a["severidade"]] = d.get(a["severidade"], 0) + 1
        return d

    seg, cor = conta("seguranca"), conta("corretude")
    abertos_graves = [a for a in ach
                      if a["severidade"] in ("critico", "alto")
                      and not a.get("refutado")
                      and a.get("status") in ("Aberto", "Em correção")]
    bloqueadores = len(abertos_graves)

    if bloqueadores == 0:
        veredito, cor_v = "Pronto pra escalar", ACENTO
    elif any(a["severidade"] == "critico" for a in abertos_graves):
        veredito, cor_v = "Não escalar", COR_SEV["critico"]
    else:
        veredito, cor_v = "Com ressalvas", COR_SEV["alto"]

    if dados["leitura"] and dados["leitura"].get("veredito"):
        mapa = {"pode_escalar": ("Pronto pra escalar", ACENTO),
                "com_ressalvas": ("Com ressalvas", COR_SEV["alto"]),
                "nao_escalar": ("Não escalar", COR_SEV["critico"])}
        veredito, cor_v = mapa.get(dados["leitura"]["veredito"], (veredito, cor_v))

    total = len([a for a in ach if not a.get("refutado")])
    fechados = len([a for a in ach if a.get("status") in ("Corrigido", "Aceito")])
    return {
        "seg": seg, "cor": cor, "bloqueadores": bloqueadores,
        "veredito": veredito, "cor_veredito": cor_v,
        "total": total, "fechados": fechados,
        "refutados": len([a for a in ach if a.get("refutado")]),
    }


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

def css_fontes() -> str:
    """Pilha de fonte de sistema. Zero requisição externa: o painel abre offline."""
    return (":root{--font-display:ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;"
            "--font-body:ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;"
            "--font-mono:ui-monospace,'Cascadia Code','JetBrains Mono',Consolas,monospace;"
            "--font-wordmark:ui-sans-serif,system-ui,sans-serif}")


def donut_svg(contagem: dict, tamanho=168) -> str:
    """Donut em SVG puro. Anima por stroke-dashoffset, sem biblioteca."""
    total = sum(contagem.values()) or 1
    r, cx = 60, tamanho / 2
    circ = 2 * 3.14159265 * r
    partes, offset = [], 0.0
    for sev in SEVERIDADES:
        v = contagem.get(sev, 0)
        if not v:
            continue
        frac = v / total
        dash = circ * frac
        partes.append(
            f'<circle class="dn" cx="{cx}" cy="{cx}" r="{r}" fill="none" '
            f'stroke="{COR_SEV[sev]}" stroke-width="16" stroke-linecap="butt" '
            f'stroke-dasharray="{dash:.2f} {circ - dash:.2f}" '
            f'stroke-dashoffset="{-offset:.2f}" transform="rotate(-90 {cx} {cx})" '
            f'data-sev="{sev}"></circle>')
        offset += dash
    return (f'<svg viewBox="0 0 {tamanho} {tamanho}" class="donut" role="img" '
            f'aria-label="Distribuição de achados por severidade">'
            f'<circle cx="{cx}" cy="{cx}" r="{r}" fill="none" stroke="#1E2127" '
            f'stroke-width="16"></circle>{"".join(partes)}</svg>')


def gauge_svg(bloqueadores: int, cor: str) -> str:
    """Medidor do gate, com o NUMERO no centro.

    Sem o numero, um anel cheio e ambiguo: pode ler como "completo, tudo certo" quando
    significa o oposto. O numero desfaz a duvida em meio segundo.
    """
    escala = min(bloqueadores, 10) / 10
    r, circ = 54, 2 * 3.14159265 * 54
    dash = circ * escala
    return (f'<svg viewBox="0 0 140 140" class="gauge" role="img" '
            f'aria-label="{bloqueadores} bloqueadores em aberto">'
            f'<circle cx="70" cy="70" r="{r}" fill="none" stroke="#1E2127" stroke-width="12"/>'
            f'<circle class="gg" cx="70" cy="70" r="{r}" fill="none" stroke="{cor}" '
            f'stroke-width="12" stroke-linecap="round" '
            f'stroke-dasharray="{dash:.2f} {circ-dash:.2f}" transform="rotate(-90 70 70)"/>'
            f'<text class="gnum" x="70" y="70" text-anchor="middle" dominant-baseline="central" '
            f'fill="{cor}">{bloqueadores}</text>'
            f'<text class="glab" x="70" y="96" text-anchor="middle" fill="#8B9086">'
            f'{"bloqueador" if bloqueadores == 1 else "bloqueadores"}</text>'
            f'</svg>')


def montar_html(dados: dict) -> str:
    run, ach, m = dados["run"], dados["achados"], metricas(dados)
    inv = dados.get("inventario", {})
    banco = inv.get("banco", {}) or {}
    codigo = inv.get("codigo", {}) or {}
    leitura = dados.get("leitura") or {}

    # Mapa de calor do schema: uma celula por tabela, cor pelo pior achado dela.
    tabelas = sorted((banco.get("tabelas") or {}).keys())
    policies_por_tabela: dict[str, int] = {}
    for p in banco.get("policies", []) or []:
        policies_por_tabela[p["tabela"]] = policies_por_tabela.get(p["tabela"], 0) + 1
    pior: dict[str, str] = {}
    ordem = {s: i for i, s in enumerate(SEVERIDADES)}
    for a in ach:
        if a.get("refutado"):
            continue
        alvo = f"{a.get('titulo','')} {a.get('objeto','')} {a.get('detalhe','')}"
        for t in tabelas:
            if re.search(rf"`{re.escape(t)}`", alvo) or f" {t} " in f" {alvo} ":
                atual = pior.get(t)
                if atual is None or ordem[a["severidade"]] < ordem[atual]:
                    pior[t] = a["severidade"]
    heat = [{
        "tabela": t,
        "policies": policies_por_tabela.get(t, 0),
        "rls": t in (banco.get("rls_habilitado") or []),
        "sev": pior.get(t),
        "dinheiro": t in (run.get("tabelas_dinheiro") or []),
    } for t in tabelas]

    payload = {
        "achados": limpar(ach),
        "status": STATUS,
        "severidades": SEVERIDADES,
        "rotuloSev": ROTULO_SEV,
        "corSev": COR_SEV,
        "heat": heat,
        "leitura": limpar(leitura),
        "matriz": limpar(dados.get("matriz")),
        "app": run.get("titulo", "App"),
        "provas": run.get("provas_de_cobertura", []),
        "lotes": run.get("lotes", []),
        "lotesLidos": dados.get("lotes_lidos", []),
        "har": limpar(dados.get("har") or {}),
    }
    # ARMADILHA CRITICA: um PoC de XSS com `</script>` literal fecha a tag no meio e
    # quebra a pagina inteira. Escapar < e > nos dados e obrigatorio, e o arquivo final
    # tem que ter EXATAMENTE UM </script>.
    dados_js = (json.dumps(payload, ensure_ascii=False)
                .replace("<", "\\u003c").replace(">", "\\u003e")
                .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))

    kpis = [
        ("Bloqueadores", m["bloqueadores"], "crítico ou alto em aberto"),
        ("Achados", m["total"], "nesta rodada"),  # nunca "confirmados": briga com o veredito do cetico
        ("Refutados", m["refutados"], "derrubados pelo cético"),
        ("Fechados", m["fechados"], "corrigidos ou aceitos"),
    ]
    kpi_html = "".join(
        f'<div class="kpi reveal"><div class="kpi-n cu" data-to="{v}">0</div>'
        f'<div class="kpi-r">{r}</div><div class="kpi-s">{s}</div></div>'
        for r, v, s in kpis)

    def barras(cont, titulo):
        total = sum(cont.values()) or 1
        linhas = []
        for sev in SEVERIDADES:
            v = cont.get(sev, 0)
            pct = v / total * 100
            linhas.append(
                f'<div class="mrow"><span class="mlab">{ROTULO_SEV[sev]}</span>'
                f'<div class="mbar"><i style="--w:{pct:.1f}%;--c:{COR_SEV[sev]}"></i></div>'
                f'<span class="mval cu" data-to="{v}">0</span></div>')
        return (f'<div class="card reveal"><h3>{titulo}</h3>'
                f'<div class="meters">{"".join(linhas)}</div></div>')

    inv_linhas = [
        ("Migrations", banco.get("arquivos_migration", 0)),
        ("Tabelas", banco.get("total_tabelas", 0)),
        ("RLS habilitado", banco.get("total_rls", 0)),
        ("Policies", banco.get("total_policies", 0)),
        ("Funções SQL", banco.get("total_funcoes", 0)),
        ("SECURITY DEFINER", banco.get("total_definer", 0)),
        ("Triggers", banco.get("total_triggers", 0)),
        ("Server functions", codigo.get("total_server_functions", 0)),
        ("Rotas de API", codigo.get("total_rotas_api", 0)),
        ("Sítios de service_role", codigo.get("total_sitios_privilegiado", 0)),
        ("Arquivos de teste", codigo.get("total_testes", 0)),
    ]
    inv_html = "".join(
        f'<div class="ivi reveal"><span class="ivl">{k}</span>'
        f'<span class="ivn cu" data-to="{v}">0</span></div>' for k, v in inv_linhas)

    plano = leitura.get("plano") or []
    plano_html = "".join(
        f'<li class="reveal"><span class="pchip">{p.get("prio","")}</span>'
        f'<div><strong>{p.get("titulo","")}</strong><p>{p.get("detalhe","")}</p></div></li>'
        for p in plano) or '<li class="vazio">Leitura de sócio ainda não gerada.</li>'

    nao_ver = leitura.get("nao_verificado") or []
    nao_ver_html = "".join(f"<li>{x}</li>" for x in nao_ver) or \
        "<li>Declarar as limitações desta rodada é obrigatório. Rode o passo da leitura.</li>"

    quando = run.get("iniciado_em", "")[:16].replace("T", " ")

    return f"""<!doctype html>
<html lang="pt-BR"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Auditoria · {run.get('titulo','App')}</title>
<style>
{css_fontes()}
*{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg:#0E1013; --bg2:#14171C; --card:#171A20; --line:#22262E;
  /* --tx3 subiu de #71766F para #8B9086: o antigo dava 4,11:1 sobre o canvas e era
     usado em texto de 11,5px, reprovando AA. O novo da 5,85:1. Medido, nao estimado. */
  --tx:#F2F3F0; --tx2:#A8ADA5; --tx3:#8B9086; --ac:{ACENTO};
  --crit:{COR_SEV['critico']}; --alt:{COR_SEV['alto']}; --med:{COR_SEV['medio']};
  --bx:{COR_SEV['baixo']}; --inf:{COR_SEV['info']};
}}
html{{scroll-behavior:smooth}}
body{{background:var(--bg);color:var(--tx);font-family:var(--font-body),system-ui;
  line-height:1.6;-webkit-font-smoothing:antialiased}}
body::before{{content:"";position:fixed;inset:0;pointer-events:none;z-index:9;opacity:.025;
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='120' height='120'%3E%3Cfilter id='n'%3E%3CfeTurbulence baseFrequency='.85' numOctaves='3'/%3E%3C/filter%3E%3Crect width='120' height='120' filter='url(%23n)'/%3E%3C/svg%3E")}}
.wrap{{max-width:1180px;margin:0 auto;padding:0 24px}}
nav{{position:sticky;top:0;z-index:20;background:rgba(14,16,19,.82);
  backdrop-filter:blur(14px);border-bottom:1px solid var(--line)}}
nav .wrap{{display:flex;align-items:center;gap:26px;height:62px;overflow-x:auto}}
.wm{{font-family:var(--font-mono),monospace;font-size:13px;letter-spacing:.04em;
  white-space:nowrap}}
.wm b{{font-weight:700;color:var(--ac)}}
nav a{{color:var(--tx2);text-decoration:none;font-size:12.5px;white-space:nowrap;
  font-family:var(--font-mono),monospace;letter-spacing:.04em;transition:color .2s}}
nav a:hover,nav a.on{{color:var(--ac)}}
nav a i{{color:var(--tx3);font-style:normal;margin-right:5px}}
section{{padding:78px 0;border-bottom:1px solid var(--line)}}
.snum{{font-family:var(--font-mono),monospace;font-size:11.5px;color:var(--ac);
  letter-spacing:.16em;margin-bottom:12px}}
h2{{font-family:var(--font-display),system-ui;font-size:clamp(24px,3.4vw,36px);
  font-weight:900;letter-spacing:-.02em;margin-bottom:10px}}
.sub{{color:var(--tx2);max-width:74ch;margin-bottom:34px}}
h3{{font-size:14px;font-weight:700;letter-spacing:.02em;margin-bottom:18px}}
.chip{{display:inline-flex;align-items:center;gap:8px;font-family:var(--font-mono),monospace;
  font-size:10.5px;letter-spacing:.14em;text-transform:uppercase;padding:6px 14px;
  border-radius:999px;border:1px solid;background:rgba(0,0,0,.32)}}
/* HERO */
.hero{{position:relative;padding:96px 0 84px;overflow:hidden}}
.hero::after{{content:"";position:absolute;width:620px;height:620px;right:-190px;top:-230px;
  border-radius:50%;background:radial-gradient(circle,{ACENTO}1F,transparent 66%);
  pointer-events:none}}
.hero h1{{font-family:var(--font-display),system-ui;font-size:clamp(34px,6vw,64px);
  font-weight:900;line-height:1.02;letter-spacing:-.035em;margin:22px 0 14px;max-width:22ch}}
.hero h1 em{{font-style:normal;color:var(--ac)}}
.gate{{display:flex;align-items:center;gap:28px;flex-wrap:wrap;margin-top:38px;
  padding:26px 30px;border-radius:20px;border:1px solid var(--line);background:var(--card)}}
.gauge{{width:126px;height:126px;flex:0 0 auto}}
.gauge .gg{{transition:stroke-dasharray 1.1s cubic-bezier(.2,.8,.2,1)}}
.gauge .gnum{{font-family:var(--font-mono),monospace;font-size:36px;font-weight:700}}
.gauge .glab{{font-family:var(--font-mono),monospace;font-size:9px;letter-spacing:.1em}}
.gate-tx strong{{display:block;font-family:var(--font-display),system-ui;font-size:26px;
  font-weight:900;letter-spacing:-.02em}}
.gate-tx p{{color:var(--tx2);font-size:14px;max-width:52ch;margin-top:6px}}
.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(178px,1fr));gap:14px;
  margin-top:22px}}
.kpi{{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:22px}}
.kpi-n{{font-family:var(--font-mono),monospace;font-size:38px;font-weight:700;
  letter-spacing:-.03em;line-height:1}}
.kpi-r{{font-size:12.5px;font-weight:700;margin-top:10px}}
.kpi-s{{font-size:11.5px;color:var(--tx3)}}
/* GRID e CARDS */
.g2{{display:grid;grid-template-columns:1fr 1fr;gap:18px}}
.g3{{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:18px}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:26px}}
.donutwrap{{display:flex;align-items:center;gap:26px;flex-wrap:wrap}}
.donut{{width:168px;height:168px}}
.donut .dn{{transition:stroke-dasharray 1.2s cubic-bezier(.2,.8,.2,1)}}
.leg{{display:flex;flex-direction:column;gap:9px}}
.leg div{{display:flex;align-items:center;gap:10px;font-size:12.5px;color:var(--tx2)}}
.leg i{{width:11px;height:11px;border-radius:3px;flex:0 0 auto}}
.meters{{display:flex;flex-direction:column;gap:13px}}
.mrow{{display:grid;grid-template-columns:66px 1fr 34px;align-items:center;gap:12px}}
.mlab{{font-size:11.5px;color:var(--tx2)}}
.mbar{{height:8px;background:#1E2127;border-radius:99px;overflow:hidden}}
.mbar i{{display:block;height:100%;width:0;background:var(--c);border-radius:99px;
  transition:width 1s cubic-bezier(.2,.8,.2,1)}}
.mbar.go i{{width:var(--w)}}
.mval{{font-family:var(--font-mono),monospace;font-size:12.5px;text-align:right}}
/* HEATMAP */
.heat{{display:grid;grid-template-columns:repeat(auto-fill,minmax(126px,1fr));gap:7px}}
.hc{{position:relative;padding:11px 12px;border-radius:10px;border:1px solid var(--line);
  background:#12151A;font-size:11px;cursor:default;transition:transform .16s,border-color .16s}}
.hc:hover{{transform:translateY(-2px);border-color:var(--ac)}}
.hc b{{display:block;font-family:var(--font-mono),monospace;font-size:10.5px;
  font-weight:500;color:var(--tx);word-break:break-all;line-height:1.35}}
.hc s{{display:block;text-decoration:none;color:var(--tx3);font-size:10px;margin-top:4px}}
.hc.sev{{border-left:3px solid var(--sc)}}
.hc .dot{{position:absolute;right:9px;top:9px;width:7px;height:7px;border-radius:50%;
  background:var(--sc)}}
.hc.money{{background:linear-gradient(180deg,#181A14,#12151A)}}
/* MATRIZ */
.mtable{{width:100%;border-collapse:collapse;font-size:12px}}
.mtable th,.mtable td{{padding:10px 12px;border-bottom:1px solid var(--line);text-align:left}}
.mleg{{font-family:var(--font-mono);font-size:11.5px;color:var(--tx2);
  margin-top:12px;line-height:1.7;max-width:74ch}}
.mtable th{{font-family:var(--font-mono),monospace;font-size:10.5px;color:var(--tx3);
  letter-spacing:.06em;font-weight:500}}
.mtable td:first-child{{font-weight:700}}
.ok{{color:var(--ac)}} .no{{color:var(--tx3)}} .warn{{color:var(--crit);font-weight:700}}
/* ACHADOS */
.tools{{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:24px;align-items:center}}
.tools select,.tools input{{background:var(--bg2);border:1px solid var(--line);
  color:var(--tx);border-radius:10px;padding:9px 13px;font-size:12.5px;
  font-family:var(--font-body),system-ui}}
.tools input{{min-width:220px}}
.btn{{background:transparent;border:1px solid var(--line);color:var(--tx2);border-radius:10px;
  padding:9px 15px;font-size:12px;cursor:pointer;font-family:var(--font-mono),monospace;
  letter-spacing:.05em;transition:border-color .2s,color .2s}}
.btn:hover{{border-color:var(--ac);color:var(--ac)}}
/* Cabecalho de grupo por severidade */
.gh{{display:flex;align-items:center;gap:12px;padding:13px 18px;margin:22px 0 10px;
  border:1px solid var(--line);border-radius:12px;background:var(--bg2);cursor:pointer;
  transition:border-color .18s,background .18s}}
.gh:hover{{border-color:var(--ac)}}
.gh.open{{background:var(--card)}}
.gpip{{width:9px;height:9px;border-radius:50%;flex:0 0 auto}}
.gt{{font-size:13px;font-weight:700;letter-spacing:.01em}}
.gq{{font-family:var(--font-mono),monospace;font-size:11.5px;color:var(--tx3);flex:1}}
/* A seta e a unica afordancia de "isso abre". Na primeira versao ela saiu em 12px na cor
   mais apagada e lia como um ponto. Tamanho e cor de texto normal, e acento no hover. */
.gseta{{color:var(--tx2);font-size:15px;line-height:1;transition:color .18s,transform .18s}}
.gh:hover .gseta{{color:var(--ac)}}
.gh.open .gseta{{color:var(--ac)}}
.gbody{{margin-bottom:6px}}
.find{{background:var(--card);border:1px solid var(--line);border-left:3px solid var(--sc);
  border-radius:14px;margin-bottom:11px;overflow:hidden}}
.fh{{display:flex;align-items:center;gap:13px;padding:17px 20px;cursor:pointer;flex-wrap:wrap}}
.fh:hover{{background:rgba(255,255,255,.016)}}
.fid{{font-family:var(--font-mono),monospace;font-size:11px;color:var(--tx3);flex:0 0 auto}}
.ft{{flex:1;min-width:200px;font-size:13.5px;font-weight:700}}
.badge{{font-family:var(--font-mono),monospace;font-size:9.5px;letter-spacing:.1em;
  text-transform:uppercase;padding:3px 9px;border-radius:99px;border:1px solid;flex:0 0 auto}}
.fb{{padding:0 20px 22px;display:none;font-size:13px;color:var(--tx2)}}
.find.open .fb{{display:block}}
/* .flab e um rotulo de campo, NAO um heading. Na v1 isto era <h4> e a pagina chegou a
   1055 headings, o que transforma o leitor de tela num indice inutil. Rotulo de campo
   nao estrutura documento. */
.fb .flab{{font-family:var(--font-mono),monospace;font-size:10px;letter-spacing:.13em;
  text-transform:uppercase;color:var(--tx3);margin:18px 0 6px;font-weight:500}}
.fh:focus-visible,.stsel:focus-visible,.btn:focus-visible,nav a:focus-visible{{
  outline:2px solid var(--ac);outline-offset:2px;border-radius:6px}}
.fb pre{{background:#0B0D10;border:1px solid var(--line);border-radius:10px;padding:13px;
  overflow-x:auto;font-family:var(--font-mono),monospace;font-size:11.5px;color:#C9CEC4;
  white-space:pre-wrap;word-break:break-word}}
.fb ul{{padding-left:19px}} .fb li{{margin:3px 0}}
.loc{{font-family:var(--font-mono),monospace;font-size:11.5px;color:var(--ac)}}
.stsel{{background:var(--bg2);border:1px solid var(--line);color:var(--tx);border-radius:8px;
  padding:5px 9px;font-size:11px;font-family:var(--font-mono),monospace}}
.vered{{display:inline-block;font-size:11px;padding:4px 10px;border-radius:8px;
  border:1px dashed var(--line);color:var(--tx2);margin-top:8px}}
/* PLANO */
.plano{{list-style:none;display:flex;flex-direction:column;gap:14px}}
.plano li{{display:flex;gap:16px;background:var(--card);border:1px solid var(--line);
  border-radius:14px;padding:19px 22px}}
.plano li.vazio{{color:var(--tx3);display:block}}
.pchip{{font-family:var(--font-mono),monospace;font-size:10.5px;letter-spacing:.08em;
  padding:5px 11px;border-radius:8px;border:1px solid var(--ac);color:var(--ac);
  height:fit-content;flex:0 0 auto}}
.plano strong{{font-size:14px}} .plano p{{color:var(--tx2);font-size:13px;margin-top:5px}}
/* INVENTARIO */
.inv{{display:grid;grid-template-columns:repeat(auto-fit,minmax(158px,1fr));gap:11px}}
.ivi{{background:var(--card);border:1px solid var(--line);border-radius:13px;padding:17px 19px}}
.ivl{{display:block;font-size:11.5px;color:var(--tx3)}}
.ivn{{font-family:var(--font-mono),monospace;font-size:25px;font-weight:700;
  letter-spacing:-.02em}}
.callout{{border:1px solid var(--line);border-left:3px solid var(--ac);border-radius:14px;
  padding:20px 24px;background:linear-gradient(90deg,{ACENTO}0A,transparent);
  display:flex;gap:15px;align-items:flex-start;margin-top:22px}}
.callout .ic{{color:var(--ac);font-size:17px;line-height:1.4}}
.callout p{{font-size:13px;color:var(--tx2)}}
.callout strong{{color:var(--tx)}}
.prova{{display:flex;flex-direction:column;gap:9px;margin-top:6px}}
.prova div{{display:flex;gap:12px;align-items:center;font-size:12.5px;color:var(--tx2);
  font-family:var(--font-mono),monospace}}
footer{{padding:52px 0 76px;color:var(--tx3);font-size:11.5px;
  font-family:var(--font-mono),monospace;line-height:1.9}}
/* REVEAL COM REDE DE SEGURANCA (regra dura).
   O padrao ingenuo (.reveal{{opacity:0}} + observer que adiciona .in) tem um modo de falha
   que e o pior possivel num relatorio: se o JS nao rodar, atrasar ou o observer nao disparar,
   o conteudo fica INVISIVEL PARA SEMPRE. A informacao existe e ninguem ve.
   Pego na verificação visual: seções inteiras saíram fantasma no screenshot.
   Solucao em duas camadas: (1) o estado default e VISIVEL, e so escondemos se o JS marcou
   `html.js`; (2) um timeout revela tudo que sobrou, aconteca o que acontecer. */
/* CONTEUDO NUNCA DEPENDE DA ANIMACAO PRA APARECER.
   Versao 1 escondia com opacity:0 e o observer devolvia. Duas rodadas de verificacao
   visual mostraram o mesmo defeito voltando por caminhos diferentes: primeiro quando o
   observer nao disparava, depois por cascata (medido: `.in` presente e opacidade 0 mesmo
   assim). Em vez de caçar a terceira variante, a classe de falha foi ELIMINADA: a
   opacidade sai da animacao e o reveal anima SO o deslocamento. Perde-se o fade, ganha-se
   a garantia de que nenhum achado de seguranca pode ficar invisivel num relatorio. */
.reveal{{opacity:1}}
html.js .reveal{{transform:translateY(14px);
  transition:transform .55s cubic-bezier(.2,.8,.2,1)}}
html.js .reveal.in{{transform:none}}
@media(max-width:820px){{.g2{{grid-template-columns:1fr}}
  section{{padding:56px 0}} .hero{{padding:66px 0 56px}}}}
@media(prefers-reduced-motion:reduce){{
  *{{transition:none!important;animation:none!important}}
  html.js .reveal,html.js .reveal.in{{opacity:1;transform:none}}}}
</style></head><body>

<nav><div class="wrap">
  <div class="wm"><b>saas-security-audit</b></div>
  <a href="#veredito"><i>01</i>Veredito</a>
  <a href="#panorama"><i>02</i>Panorama</a>
  <a href="#schema"><i>03</i>Schema</a>
  <a href="#matriz"><i>04</i>Matriz</a>
  <a href="#achados"><i>05</i>Achados</a>
  <a href="#plano"><i>06</i>Plano</a>
  <a href="#cobertura"><i>07</i>Cobertura</a>
</div></nav>

<header class="hero" id="veredito"><div class="wrap">
  <span class="chip" style="border-color:{ACENTO};color:{ACENTO}">AUDITORIA · SEGURANÇA E CORRETUDE</span>
  <h1>{run.get('titulo','App')}, auditado em <em>duas dimensões</em></h1>
  <p class="sub">Abuso (o que um atacante alcança) e corretude (onde o sistema erra sozinho
  com quem age de boa-fé). Rodada de {quando}, modo {run.get('modo','completa')}.
  Leitura estática e passiva: nada foi alterado, nada foi executado contra produção.</p>

  <div class="gate">
    {gauge_svg(m['bloqueadores'], m['cor_veredito'])}
    <div class="gate-tx">
      <span class="chip" style="border-color:{m['cor_veredito']};color:{m['cor_veredito']}">
        Pronto pra escalar?</span>
      <strong style="color:{m['cor_veredito']};margin-top:10px">{m['veredito']}</strong>
      <p><b class="cu" data-to="{m['bloqueadores']}">0</b> {'bloqueador' if m['bloqueadores'] == 1 else 'bloqueadores'} em aberto,
      contando crítico e alto que ainda não foram corrigidos ou aceitos.
      {leitura.get('resumo','')}</p>
    </div>
  </div>
  <div class="kpis">{kpi_html}</div>
</div></header>

<main>
<section id="panorama"><div class="wrap">
  <div class="snum">02</div><h2>Panorama por dimensão</h2>
  <p class="sub">Segurança e corretude contam separado de propósito: uma não maquia a outra.
  Achado refutado pelo cético sai da conta de bloqueador e fica registrado como informativo.</p>
  <div class="g2">
    <div class="card reveal"><h3>Distribuição por severidade</h3>
      <div class="donutwrap">{donut_svg({k: m['seg'].get(k,0)+m['cor'].get(k,0) for k in SEVERIDADES})}
        <div class="leg">
          {''.join(f'<div><i style="background:{COR_SEV[s]}"></i>{ROTULO_SEV[s]} '
                   f'<b class="cu" data-to="{m["seg"].get(s,0)+m["cor"].get(s,0)}">0</b></div>'
                   for s in SEVERIDADES)}
        </div>
      </div>
    </div>
    <div style="display:flex;flex-direction:column;gap:18px">
      {barras(m['seg'], 'Dimensão A · Segurança e abuso')}
      {barras(m['cor'], 'Dimensão B · Corretude de negócio')}
    </div>
  </div>
  <div class="callout"><span class="ic">◆</span><p><strong>A dimensão B não existe nos checklists de mercado.</strong>
  Auditoria de segurança pergunta o que um atacante alcança. Corretude pergunta se o sistema
  faz a coisa certa com quem age de boa-fé, e a severidade é medida por consequência: cobrar
  quem não devia é pior que negar quem tem direito.</p></div>
</div></section>

<section id="schema"><div class="wrap">
  <div class="snum">03</div><h2>Mapa de calor do schema</h2>
  <p class="sub">{
    f"Uma célula por tabela do banco, todas as {banco.get('total_tabelas', 0)}. "
    "É a prova de cobertura em forma de imagem: nenhuma tabela ficou fora, e a cor marca o pior "
    "achado de cada uma."
    if banco.get('total_tabelas', 0)
    else "Este app não tem banco de dados, então não existe schema para mapear. "
         "O zero abaixo é medido e declarado, e por isso não recebe selo de cobertura provada."
  }</p>
  <div class="heat" id="heat"></div>
  <div class="inv" style="margin-top:30px">{inv_html}</div>
</div></section>

<section id="matriz"><div class="wrap">
  <div class="snum">04</div><h2>Matriz de acesso</h2>
  <p class="sub">Cada tipo de acesso contra cada guarda. É a única lente que não se
  particiona: o defeito mora no cruzamento, então fatiar esconderia exatamente o que ela
  existe pra achar.</p>
  <div class="card"><div style="overflow-x:auto"><table class="mtable" id="tab-matriz"></table></div></div>
</div></section>

<section id="achados"><div class="wrap">
  <div class="snum">05</div><h2>Achados</h2>
  <p class="sub">Status editável: mudar aqui move as barras e o gate ao vivo, e persiste no
  navegador. Exporte o JSON pra atravessar rodadas sem reabrir o que você já julgou.</p>
  <div class="tools">
    <select id="fdim" aria-label="Filtrar por dimensão"><option value="">Todas as dimensões</option>
      <option value="seguranca">Segurança</option><option value="corretude">Corretude</option></select>
    <select id="fsev" aria-label="Filtrar por severidade"><option value="">Todas as severidades</option></select>
    <select id="fsta" aria-label="Filtrar por status"><option value="">Todos os status</option></select>
    <input id="fq" aria-label="Buscar achado" placeholder="Buscar título, arquivo, categoria">
    <button class="btn" id="exp">Exportar status</button>
    <span id="cnt" style="font-size:12px;color:var(--tx3)"></span>
  </div>
  <div id="lista"></div>
</div></section>

<section id="plano"><div class="wrap">
  <div class="snum">06</div><h2>Plano de correção</h2>
  <p class="sub">Prioridade amarrada a marco de negócio, não a calendário: prazo medido em
  data vira "próxima semana" pra sempre.</p>
  <ul class="plano">{plano_html}</ul>
  <div class="callout" style="border-left-color:var(--alt)">
    <span class="ic" style="color:var(--alt)">▲</span>
    <div><p><strong>O que esta auditoria NÃO viu.</strong> Auditoria que não declara o próprio
    limite mente por omissão.</p>
    <ul style="margin-top:8px;padding-left:18px">{nao_ver_html}</ul></div></div>
</div></section>

<section id="cobertura"><div class="wrap">
  <div class="snum">07</div><h2>Prova de cobertura</h2>
  <p class="sub">Aritmética, não promessa. O scanner particiona com lista explícita e valida
  por asserção que a soma dos lotes é igual ao universo e que a interseção é vazia. Amostragem
  esconde.</p>
  <div class="g3">
    {''.join(f'<div class="card reveal"><h3>{p.get("rotulo","")}</h3><div class="prova">'
             f'<div><span class="{"ok" if p.get("ok") else "warn"}">'
             f'{"✓ OK" if p.get("ok") else "✗ FALHOU"}</span></div>'
             f'<div>universo <b class="cu" data-to="{p.get("universo",0)}">0</b></div>'
             f'<div>soma dos lotes <b class="cu" data-to="{p.get("soma_dos_lotes",0)}">0</b></div>'
             f'<div>sobreposição <b class="cu" data-to="{len(p.get("sobreposicao",[]))}">0</b></div>'
             f'</div></div>' for p in run.get('provas_de_cobertura', []))}
  </div>
  <div class="card reveal" style="margin-top:18px"><h3>Lotes do manifesto</h3>
    <div style="overflow-x:auto"><table class="mtable">
    <tr><th>Lote</th><th>Itens</th><th>Dimensões</th><th>Executor</th><th>Resultado</th></tr>
    {''.join(f'<tr><td>{l.get("id")}</td><td>{l.get("qtd")}</td>'
             f'<td>{", ".join(l.get("dimensoes",[]))}</td>'
             f'<td>{"orquestrador" if l.get("executor")=="orquestrador" else "subagente"}</td>'
             f'<td class="{"ok" if l.get("id") in dados.get("lotes_lidos",[]) else "no"}">'
             f'{"gravado" if l.get("id") in dados.get("lotes_lidos",[]) else "pendente"}</td></tr>'
             for l in run.get('lotes', []))}
    </table></div></div>
</div></section>

</main>

<footer><div class="wrap">
  Auditoria estática e passiva · nada foi alterado no app · segredos mascarados<br>
  Perfil: {run.get('perfil_hash','?')} · modo {run.get('modo','?')} ·
  gerado em {datetime.now():%Y-%m-%d %H:%M}<br>
  gerado por saas-security-audit · ALQUIM_IA.LAB · Apache-2.0
</div></footer>

<script>
/* Marca que o JS esta vivo. Só a partir daqui o CSS esconde o que vai animar:
   sem isto, JS quebrado deixaria a pagina em branco. */
document.documentElement.classList.add('js');
var D = {dados_js};

function el(t, c, tx) {{
  var e = document.createElement(t);
  if (c) e.className = c;
  if (tx !== undefined && tx !== null) e.textContent = String(tx);
  return e;
}}
function loc(a) {{
  var s = a.arquivo || '';
  if (a.linha) s += ':' + a.linha;
  return s;
}}

/* ---------- MAPA DE CALOR ---------- */
(function () {{
  var box = document.getElementById('heat');
  D.heat.forEach(function (h) {{
    var c = el('div', 'hc' + (h.sev ? ' sev' : '') + (h.dinheiro ? ' money' : ''));
    if (h.sev) c.style.setProperty('--sc', D.corSev[h.sev]);
    c.appendChild(el('b', null, h.tabela));
    var det = (h.rls ? 'RLS on' : 'SEM RLS') + ' · ' + h.policies + ' policy';
    c.appendChild(el('s', null, det));
    if (h.sev) {{
      var d = el('span', 'dot');
      d.style.setProperty('--sc', D.corSev[h.sev]);
      c.appendChild(d);
    }}
    /* sem travessao: e banido de forma binaria pela casa, e este title e texto que
       o leitor ve no hover. */
    c.title = h.tabela + ', ' + det + (h.sev ? '. Pior achado: ' + D.rotuloSev[h.sev] : '');
    box.appendChild(c);
  }});
}})();

/* ---------- MATRIZ DE ACESSO ---------- */
(function () {{
  var t = document.getElementById('tab-matriz');
  var m = D.matriz || null;
  if (!m) {{
    var tr = el('tr'), td = el('td', null,
      'A matriz é montada no lote matriz-01, pelo orquestrador. Rode a fase de corretude.');
    td.colSpan = 4; td.style.color = 'var(--tx3)';
    tr.appendChild(td); t.appendChild(tr);
    return;
  }}
  var head = el('tr');
  var th0 = el('th', null, 'Tipo de acesso'); th0.setAttribute('scope', 'col');
  head.appendChild(th0);
  m.colunas.forEach(function (c) {{
    var th = el('th', null, c); th.setAttribute('scope', 'col'); head.appendChild(th);
  }});
  t.appendChild(head);
  m.linhas.forEach(function (l) {{
    var tr = el('tr');
    /* cabecalho de LINHA: sem isto, cada uma das 63 celulas anuncia so a coluna
       no leitor de tela, e numa matriz o dado so existe no cruzamento. */
    var th = el('th', null, l.tipo); th.setAttribute('scope', 'row');
    tr.appendChild(th);
    l.celulas.forEach(function (v) {{
      var mapa = {{'OK':'✓ ok','NAO':'✗ não','ATENCAO':'⚠ atenção','n/a':'· n/a'}};
      var txt = mapa[v] !== undefined ? mapa[v] : v;
      var cls = (v === 'ATENCAO' || v === '⚠') ? 'warn' : ((v === 'OK' || v === '✓') ? 'ok' : 'no');
      tr.appendChild(el('td', cls, txt));
    }});
    t.appendChild(tr);
  }});
  /* ⚠️ A LEGENDA E RENDERIZADA. O campo `legenda_visivel` ja chegava
     no dado e nunca era impresso: 63 celulas com 4 simbolos e nenhuma chave na
     tela. O pior caso e o simbolo de "ignora, e o esperado", que desenhado em
     cinza ao lado de linhas vermelhas le como defeito quando e o certo. */
  if (m.legenda_visivel) {{
    var cap = el('p', 'mleg', m.legenda_visivel);
    t.parentNode.appendChild(cap);
  }}
}})();

/* ---------- ACHADOS ---------- */
var KEY = 'auditor:' + (D.app || 'app');
var salvo = {{}};
try {{ salvo = JSON.parse(localStorage.getItem(KEY) || '{{}}'); }} catch (e) {{}}
D.achados.forEach(function (a) {{ if (salvo[a.id_estavel]) a.status = salvo[a.id_estavel]; }});

var selSev = document.getElementById('fsev');
D.severidades.forEach(function (s) {{
  var o = el('option', null, D.rotuloSev[s]); o.value = s; selSev.appendChild(o);
}});
var selSta = document.getElementById('fsta');
D.status.forEach(function (s) {{
  var o = el('option', null, s); o.value = s; selSta.appendChild(o);
}});

function bloco(rot, txt) {{
  var f = document.createDocumentFragment();
  if (!txt) return f;
  f.appendChild(el('div', 'flab', rot));
  f.appendChild(el('p', null, txt));
  return f;
}}

function card(a) {{
  var d = el('div', 'find');
  d.style.setProperty('--sc', D.corSev[a.severidade] || '#555');
  var h = el('div', 'fh');
  h.appendChild(el('span', 'fid', a.id));
  h.appendChild(el('span', 'ft', a.titulo));

  var b = el('span', 'badge', D.rotuloSev[a.severidade] || a.severidade);
  b.style.borderColor = D.corSev[a.severidade]; b.style.color = D.corSev[a.severidade];
  h.appendChild(b);
  var bd = el('span', 'badge', a.dimensao === 'corretude' ? 'corretude' : 'segurança');
  bd.style.borderColor = 'var(--line)'; bd.style.color = 'var(--tx2)';
  h.appendChild(bd);
  if (a.lente) {{
    var bl = el('span', 'badge', a.lente);
    bl.style.borderColor = 'var(--ac)'; bl.style.color = 'var(--ac)';
    h.appendChild(bl);
  }}
  if (a.veredito) {{
    var bv = el('span', 'badge', a.veredito
      + (a.severidade_original && a.severidade_original !== a.severidade
         ? ' ' + a.severidade_original + '→' + a.severidade : ''));
    bv.style.borderColor = a.veredito === 'refutado' ? 'var(--tx3)' : 'var(--ac)';
    bv.style.color = a.veredito === 'refutado' ? 'var(--tx3)' : 'var(--ac)';
    h.appendChild(bv);
  }}
  if (a.nao_implantado) {{
    var bn = el('span', 'badge', 'corrigido, não implantado');
    bn.style.borderColor = 'var(--alt)'; bn.style.color = 'var(--alt)';
    h.appendChild(bn);
  }}
  if (a.confianca === 'plausivel') {{
    var bc = el('span', 'badge', 'a confirmar');
    bc.style.borderColor = 'var(--med)'; bc.style.color = 'var(--med)';
    h.appendChild(bc);
  }}

  var sel = el('select', 'stsel');
  D.status.forEach(function (s) {{
    var o = el('option', null, s); o.value = s;
    if (s === (a.status || 'Aberto')) o.selected = true;
    sel.appendChild(o);
  }});
  sel.setAttribute('aria-label', 'Status do achado ' + a.id + ': ' + a.titulo);
  sel.onclick = function (e) {{ e.stopPropagation(); }};
  sel.onkeydown = function (e) {{ e.stopPropagation(); }};
  sel.onchange = function () {{
    a.status = sel.value; salvo[a.id_estavel] = sel.value;
    localStorage.setItem(KEY, JSON.stringify(salvo)); render();
  }};
  h.appendChild(sel);

  /* O cabecalho e um controle de verdade: abre e fecha o achado. Sem role, tabindex e
     tecla, um relatorio de seguranca fica inteiramente inacessivel por teclado. */
  h.setAttribute('role', 'button');
  h.setAttribute('tabindex', '0');
  h.setAttribute('aria-expanded', 'false');
  function alterna() {{
    var aberto = d.classList.toggle('open');
    h.setAttribute('aria-expanded', aberto ? 'true' : 'false');
  }}
  h.onclick = alterna;
  h.onkeydown = function (e) {{
    if (e.key === 'Enter' || e.key === ' ') {{ e.preventDefault(); alterna(); }}
  }};
  d.appendChild(h);

  var body = el('div', 'fb');
  if (loc(a)) {{
    body.appendChild(el('div', 'flab', 'Localização'));
    body.appendChild(el('div', 'loc', loc(a)));
  }}
  (a.localizacoes_extra || []).forEach(function (l) {{
    body.appendChild(el('div', 'loc', l));
  }});
  if (a.evidencia) {{
    body.appendChild(el('div', 'flab', 'Evidência'));
    body.appendChild(el('pre', null, a.evidencia));
  }}
  body.appendChild(bloco('O que é', a.detalhe));
  body.appendChild(bloco('Por que importa', a.por_que));
  body.appendChild(bloco('Cenário', a.cenario));
  body.appendChild(bloco('Causa raiz', a.causa_raiz));
  body.appendChild(bloco('Correção proposta', a.correcao));
  body.appendChild(bloco('Teste que prende o achado', a.teste));
  body.appendChild(bloco('Confiança', a.confianca
    ? a.confianca + (a.por_que_confianca ? ' · ' + a.por_que_confianca : '') : ''));

  var bl = (a.bloqueadores_cetico || []).concat(a.bloqueadores_procurados || []);
  if (bl.length) {{
    body.appendChild(el('div', 'flab', 'Bloqueadores procurados'));
    var ul = el('ul');
    bl.forEach(function (x) {{
      if (typeof x === 'string') {{ ul.appendChild(el('li', null, x)); return; }}
      var txt = (x.encontrado ? '✓ ' : '✗ ') + (x.bloqueador || '');
      /* idem: virgula no lugar do travessao, e este texto aparece sem hover,
         dentro de qualquer achado expandido que tenha bloqueador. */
      if (x.onde) txt += ', ' + x.onde;
      if (x.efeito) txt += ', ' + x.efeito;
      ul.appendChild(el('li', null, txt));
    }});
    body.appendChild(ul);
  }}
  if (a.justificativa_cetico) {{
    var v = el('div', 'vered', 'Cético: ' + a.justificativa_cetico);
    body.appendChild(v);
  }}
  if (a.razao_baseline) {{
    body.appendChild(el('div', 'vered', 'Decisão anterior: ' + a.razao_baseline));
  }}
  d.appendChild(body);
  return d;
}}

/* AGRUPAMENTO POR SEVERIDADE.
   143 achados numa lista plana e um paredao: a pessoa rola, cansa e para de ler, e o
   critico some no meio do baixo. Agrupar resolve sem esconder nada: o que trava a
   escalada (critico e alto) nasce ABERTO, o resto nasce recolhido com a contagem a
   vista. Um clique, ou Enter, abre. O estado de cada grupo persiste durante a sessao,
   pra o filtro nao ficar reabrindo o que voce fechou. */
var gruposAbertos = {{critico: true, alto: true, medio: false, baixo: false, info: false}};

function cabecalhoGrupo(sev, qtd, aberto) {{
  var h = el('div', 'gh' + (aberto ? ' open' : ''));
  h.setAttribute('role', 'button');
  h.setAttribute('tabindex', '0');
  h.setAttribute('aria-expanded', aberto ? 'true' : 'false');
  var pip = el('i', 'gpip');
  pip.style.background = D.corSev[sev];
  h.appendChild(pip);
  h.appendChild(el('span', 'gt', D.rotuloSev[sev]));
  h.appendChild(el('span', 'gq', qtd + (qtd === 1 ? ' achado' : ' achados')));
  h.appendChild(el('span', 'gseta', aberto ? '▾' : '▸'));
  function alterna() {{
    gruposAbertos[sev] = !gruposAbertos[sev];
    render();
  }}
  h.onclick = alterna;
  h.onkeydown = function (e) {{
    if (e.key === 'Enter' || e.key === ' ') {{ e.preventDefault(); alterna(); }}
  }};
  return h;
}}

function render() {{
  var dim = document.getElementById('fdim').value;
  var sev = document.getElementById('fsev').value;
  var sta = document.getElementById('fsta').value;
  var q = document.getElementById('fq').value.toLowerCase();
  var lista = document.getElementById('lista');
  lista.textContent = '';

  var porSev = {{}};
  D.severidades.forEach(function (s) {{ porSev[s] = []; }});
  var n = 0;
  D.achados.forEach(function (a) {{
    if (dim && a.dimensao !== dim) return;
    if (sev && a.severidade !== sev) return;
    if (sta && (a.status || 'Aberto') !== sta) return;
    if (q) {{
      var hay = [a.titulo, a.arquivo, a.categoria, a.detalhe, a.id].join(' ').toLowerCase();
      if (hay.indexOf(q) < 0) return;
    }}
    (porSev[a.severidade] || (porSev[a.severidade] = [])).push(a); n++;
  }});

  D.severidades.forEach(function (s) {{
    var itens = porSev[s] || [];
    if (!itens.length) return;
    // Busca ativa abre todos os grupos: quem procurou espera ver o resultado.
    var aberto = q ? true : gruposAbertos[s];
    lista.appendChild(cabecalhoGrupo(s, itens.length, aberto));
    if (!aberto) return;
    var box = el('div', 'gbody');
    itens.forEach(function (a) {{ box.appendChild(card(a)); }});
    lista.appendChild(box);
  }});

  if (!n) {{
    var v = el('p', null, 'Nenhum achado com esses filtros.');
    v.style.color = 'var(--tx3)'; lista.appendChild(v);
  }}
  document.getElementById('cnt').textContent = n + ' de ' + D.achados.length;
  atualizarGate();
}}

/* O gate e as barras reagem ao status ao vivo: e o que torna o painel ferramenta
   de trabalho em vez de documento que envelhece. */
function atualizarGate() {{
  var bloq = D.achados.filter(function (a) {{
    return (a.severidade === 'critico' || a.severidade === 'alto')
      && !a.refutado
      && (a.status === 'Aberto' || a.status === 'Em correção' || !a.status);
  }}).length;
  var cor = bloq === 0 ? '{ACENTO}'
    : (D.achados.some(function (a) {{
        return a.severidade === 'critico' && !a.refutado
          && (a.status === 'Aberto' || a.status === 'Em correção' || !a.status);
      }}) ? D.corSev.critico : D.corSev.alto);
  var txt = bloq === 0 ? 'Pronto pra escalar'
    : (cor === D.corSev.critico ? 'Não escalar' : 'Com ressalvas');
  var g = document.querySelector('.gate-tx strong');
  if (g) {{ g.textContent = txt; g.style.color = cor; }}
  var chip = document.querySelector('.gate-tx .chip');
  if (chip) {{ chip.style.borderColor = cor; chip.style.color = cor; }}
  var arc = document.querySelector('.gauge .gg');
  if (arc) {{
    var circ = 2 * Math.PI * 54, f = Math.min(bloq, 10) / 10;
    arc.setAttribute('stroke-dasharray', (circ * f) + ' ' + (circ - circ * f));
    arc.setAttribute('stroke', cor);
  }}
}}

['fdim', 'fsev', 'fsta'].forEach(function (id) {{
  document.getElementById(id).onchange = render;
}});
document.getElementById('fq').oninput = render;
document.getElementById('exp').onclick = function () {{
  var out = {{}};
  D.achados.forEach(function (a) {{
    out[a.id_estavel] = {{ id: a.id, titulo: a.titulo, severidade: a.severidade,
      status: a.status || 'Aberto' }};
  }});
  var blob = new Blob([JSON.stringify(out, null, 2)], {{ type: 'application/json' }});
  var u = URL.createObjectURL(blob), l = document.createElement('a');
  l.href = u; l.download = 'auditoria-status.json'; l.click();
  URL.revokeObjectURL(u);
}};

/* ---------- MOVIMENTO: count-up e reveal, disparados AO ENTRAR NA TELA ----------
   Se animar no load, a animacao toca com a secao fora do viewport e ninguém vê. */
/* ⚠️ O media query de reduced-motion so desliga transition e animation de CSS.
   Este contador e requestAnimationFrame puro, entao precisa do proprio guarda:
   sem ele, 20 numeros ficam girando na tela de quem pediu o movimento parar. */
var SEM_MOVIMENTO = window.matchMedia
  && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
function contar(e) {{
  var alvo = parseFloat(e.dataset.to || '0'), t0 = null, dur = 1100;
  if (SEM_MOVIMENTO) {{ e.textContent = alvo.toLocaleString('pt-BR'); return; }}
  function passo(ts) {{
    if (!t0) t0 = ts;
    var p = Math.min((ts - t0) / dur, 1), ease = 1 - Math.pow(1 - p, 3);
    e.textContent = Math.round(alvo * ease).toLocaleString('pt-BR');
    if (p < 1) requestAnimationFrame(passo);
  }}
  requestAnimationFrame(passo);
}}
var io = new IntersectionObserver(function (ents) {{
  ents.forEach(function (en) {{
    if (!en.isIntersecting) return;
    var t = en.target;
    t.classList.add('in');
    if (t.classList.contains('cu')) contar(t);
    t.querySelectorAll && t.querySelectorAll('.cu').forEach(contar);
    t.querySelectorAll && t.querySelectorAll('.mbar').forEach(function (b) {{
      b.classList.add('go');
    }});
    io.unobserve(t);
  }});
}}, {{ threshold: 0.15 }});
function observar() {{
  document.querySelectorAll('.reveal,.cu,.card,.mbar').forEach(function (e) {{
    io.observe(e);
  }});
}}
/* REDE DE SEGURANCA: depois de 2s, revela tudo que ainda esta escondido e roda o
   count-up e as barras que ficaram pra tras. Animacao e enfeite; conteudo invisivel
   e defeito. Nenhuma informacao deste relatorio pode depender de um observer disparar. */
function revelarTudo() {{
  document.querySelectorAll('.reveal:not(.in)').forEach(function (e) {{
    e.classList.add('in');
  }});
  document.querySelectorAll('.cu').forEach(function (e) {{
    if (e.textContent === '0' && (e.dataset.to || '0') !== '0') contar(e);
  }});
  document.querySelectorAll('.mbar:not(.go)').forEach(function (b) {{
    b.classList.add('go');
  }});
}}
render();
observar();
atualizarGate();
setTimeout(revelarTudo, 1200);
window.addEventListener('beforeprint', revelarTudo);

/* nav ativa */
var secs = document.querySelectorAll('section,header.hero');
var navio = new IntersectionObserver(function (ents) {{
  ents.forEach(function (en) {{
    if (!en.isIntersecting) return;
    document.querySelectorAll('nav a').forEach(function (a) {{
      a.classList.toggle('on', a.getAttribute('href') === '#' + en.target.id);
    }});
  }});
}}, {{ threshold: 0.3 }});
secs.forEach(function (s) {{ navio.observe(s); }});
</script>
</body></html>"""


def main():
    ap = argparse.ArgumentParser(description="Painel da skill /auditor")
    ap.add_argument("--pasta", type=Path, required=True,
                    help="pasta da execução: <saida>/<app>/AAAA-MM-DD-modo")
    ap.add_argument("--abrir", action="store_true")
    args = ap.parse_args()

    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8")
        except Exception:
            pass

    pasta = args.pasta.resolve()
    if not (pasta / "run.json").is_file():
        raise SystemExit(f"run.json nao encontrado em {pasta}. Rode o scanner.py primeiro.")

    dados = coletar(pasta)
    html = montar_html(dados)

    # Trava do </script>: se der mais de 1, algum dado escapou e a pagina quebra.
    n = html.count("</script>")
    if n != 1:
        raise SystemExit(f"ABORTADO: o HTML tem {n} '</script>' (deveria ser 1). "
                         "Algum dado nao foi escapado e a pagina quebraria.")

    destino = pasta / "relatorio.html"
    destino.write_text(html, encoding="utf-8")
    latest = pasta.parent / "latest.html"
    shutil.copyfile(destino, latest)
    gravar_baseline(dados)

    m = metricas(dados)
    print(f"Painel: {destino}")
    print(f"Atalho: {latest}")
    print(f"Veredito: {m['veredito']} · {m['bloqueadores']} bloqueador(es) · "
          f"{m['total']} achados ({m['refutados']} refutados)")
    print(f"Baseline: {dados['baseline_path']}")
    if not dados.get("leitura"):
        print("AVISO: leitura.json ausente. Rode o passo do `claude -p` "
              "(prompts/leitura.md) e regenere.")

    if args.abrir:
        webbrowser.open(destino.as_uri())


if __name__ == "__main__":
    main()
