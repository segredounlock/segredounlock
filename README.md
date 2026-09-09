<!-- Vitrine pública do perfil — SegredoiDev / CentralDark -->
<!-- Projeção pública. GitHub/CI/runtime continuam sendo a prova. -->

<p align="center">
  <img src="https://img.lightshot.app/KHRgZKXlS6W62e_ibXCDuQ.png" width="720" alt="CentralDark" />
</p>

<h1 align="center">SegredoiDev 👋</h1>

<p align="center">
  <img src="https://i.imgur.com/pV3hmbA.gif" width="120" alt="Mascote CentralDark" />
</p>

<p align="center">
  <b>SEGREDO/CHEFE</b> · construindo e operando o <strong>CentralDark</strong><br/>
  Intenção humana → coordenação → execução reversível → prova → aprendizado.
</p>

<p align="center">
  <img src="https://komarev.com/ghpvc/?username=segredounlock&label=Visitas&color=7c3aed&style=for-the-badge" alt="visitas" />
  <img src="https://img.shields.io/badge/dynamic/json?label=Seguidores&query=%24.followers&url=https%3A%2F%2Fapi.github.com%2Fusers%2Fsegredounlock&style=for-the-badge&color=0e75b6&logo=github" alt="seguidores" />
  <img src="https://img.shields.io/badge/ONE_SYSTEM-ONLY-111827?style=for-the-badge" alt="one system" />
  <img src="https://img.shields.io/badge/UNKNOWN-%E2%89%A0_PASS-7c3aed?style=for-the-badge" alt="unknown não é pass" />
  <img src="https://img.shields.io/badge/CORE-PRIVATE-0f172a?style=for-the-badge&logo=github" alt="core privado" />
</p>

---
## 🧭 O que é o CentralDark hoje

O **CentralDark** é o sistema que estou construindo para juntar, no mesmo organismo, automação, agentes, GitHub, VPS, Windows/Casa, MCP e conectores, memória e recuperação de contexto, voz/multimodal, observabilidade e prova operacional.

Não é “um modelo de IA” no centro e não é uma coleção de bots soltos. Modelos entram como **motores substituíveis** dentro de um fluxo único, com objetivo humano preservado e estado real medido antes de qualquer conclusão.

```text
SEGREDO/CHEFE = objetivo + autoridade humana final
SOL            = coordenação e reconciliação
PIVETE/HERMES  = execução + preservação + continuidade
MODELOS        = motores substituíveis
REALIDADE      = juiz do estado observável no escopo atual
```

### Leis operacionais

```text
ONE_SYSTEM_ONLY
REUSE_BEFORE_CREATE
ONE_WRITER_PER_SCOPE
UNKNOWN != PASS
DOCUMENTED != EXECUTED
MERGED != DEPLOYED
NO_BLIND_OVERWRITE
```

---
## ⚖️ REALITY=JUDGE, sem “verdade absoluta”

Aqui, **REALITY=JUDGE** não significa uma máquina da verdade eterna.
Significa: diante de um domínio, premissas, instrumentos, alvo e evidências declaradas, qual é o **melhor estado justificável agora**?

```text
CLAIM
→ DOMÍNIO + PREMISSAS
→ OBSERVADORES + HEAD/TEMPO
→ PROVA FORMAL quando aplicável
→ MEDIÇÃO EMPÍRICA quando aplicável
→ CONTRAPROVA
→ META-JUIZ independente
→ VEREDITO NO ESCOPO
```

Estados possíveis:

```text
PROVED_IN_SCOPE
REFUTED_IN_SCOPE
UNKNOWN
UNDECIDABLE_IN_MODEL
OUT_OF_SCOPE
```

Um teorema formal não substitui medição física. Um HTTP 200 não prova o sistema inteiro. Um painel verde não prova produção. E um provador não recebe licença para certificar a própria conclusão sem âncora independente.

---
## 🧠 Lógica, autorreferência e limites

A arquitetura separa quatro coisas que costumam ser misturadas:

1. **Derivação formal** — o que segue das regras e fatos declarados.
2. **Observação empírica** — o que instrumentos realmente mediram.
3. **Metalinguagem** — quem avalia o próprio sistema de prova.
4. **Limite** — o que não pode ser decidido com o modelo ou evidência disponível.

A inspiração prática vem de lógica computacional, falsificação e dos limites de autorreferência: se uma conclusão depende de o próprio provador dizer “eu estou correto”, ela não fecha o circuito sozinha.

O paradoxo de Aquiles e a tartaruga lembra outra diferença útil: uma descrição pode conter infinitas subdivisões sem obrigar o mundo físico a executar uma sequência infinita de operações. Modelo e fenômeno não são a mesma coisa.

```text
FORMAL_PROOF != EMPIRICAL_PROOF
EMPIRICAL_EVIDENCE != ABSOLUTE_TRUTH
SELF_REFERENCE_REQUIRES_META_LEVEL
NO_DECISION_AVAILABLE => UNKNOWN
FIXED_POINT = fechamento no escopo, não verdade metafísica final
```

---

## 🧪 Harness de prova e ataque

O **harness** é a bancada onde claims são pressionados antes de ganhar verde. Ele não é o juiz final; é um instrumento adversarial reproduzível.
Ele serve para:

- injetar ausência, corrupção, atraso, conflito e evidência contraditória;
- repetir o mesmo teste em condições positivas, negativas e de limite;
- verificar integridade de receipts e detectar tamper;
- provar que `UNKNOWN`, `QUEUED`, `SKIPPED` e `CANCELLED` não vazam como PASS;
- separar Writer, Prover e Judge para reduzir prova circular;
- comparar dois observadores e exigir reconciliação quando divergem;
- produzir receipt com alvo, SHA, premissas, evidência, contraprova e escopo do ponto fixo.

```text
CLAIM
  ↓
HARNESS ADVERSARIAL
  ├─ positive test
  ├─ negative test
  ├─ boundary test
  ├─ tamper test
  ├─ counterexample
  └─ rollback/recovery
  ↓
EVIDENCE LEDGER
  ↓
META-JUDGE
  ↓
PROVED_IN_SCOPE | REFUTED_IN_SCOPE | UNKNOWN
```

A pasta pública `mae/` é uma bancada pequena dessa ideia: ataques S1/S3/S6 em sandbox contra orphan BEGIN, adulteração de hash e remoção de FINAL.

---
## ⚙️ Frentes vivas

- 🧠 **Orquestração model-neutral** — um core, múltiplos motores e coordenação por escopo
- 🔄 **Continuidade e retomada** — estado, receipts, cursores e reconciliação antes de seguir
- 🧪 **Prova e contraprova** — same-head CI, falsificação e zero falso-verde
- 🛠️ **GitHub Actions self-hosted** — fila, promoção segura, dependências e conflitos
- 🔌 **MCP + conectores** — ferramentas e runtime sem transformar transporte em autoridade
- 🎙️ **Voz e multimodal** — áudio, TTS, percepção e integração com superfícies locais
- 🧭 **Memória e recuperação** — contexto com proveniência, dedupe e aprendizado reutilizável
- ♻️ **Execução reversível** — menor delta, health, rollback e re-medição

---

## 🌐 Vitrine pública × núcleo privado

O núcleo do **CentralDark** vive em repositório privado. Esta página é a **entrada pública**, não uma cópia do sistema inteiro.

```text
README público = explicação / vitrine
GitHub privado = código + histórico + contratos
CI             = teste do HEAD
Casa / VPS     = execução observada
Runtime        = prova de funcionamento
```

Se um endpoint, deploy ou integração não estiver medido agora, eu prefiro marcar **UNKNOWN** em vez de vender verde decorativo.

<p align="center">
  <a href="https://github.com/ServerVpss"><img src="https://img.shields.io/badge/Organiza%C3%A7%C3%A3o-ServerVpss-111827?style=for-the-badge&logo=github" alt="ServerVpss" /></a>
</p>

---
## 🧰 Stack principal

<p align="center">
  <img src="https://skillicons.dev/icons?i=ts,react,vite,tailwind,nodejs,bun,python,powershell,postgres,docker,linux,bash,github,githubactions,vscode" alt="Stack principal" />
</p>

```text
TypeScript / React / Node / Bun
Python / PowerShell / Bash
PostgreSQL / Supabase
Docker / Linux / Windows
GitHub Actions / runners self-hosted
MCP / APIs / automação / observabilidade
```

---

## 📸 Painel completo <sub>(atualiza a cada 6h)</sub>

<p align="center">
  <img src="https://raw.githubusercontent.com/segredounlock/segredounlock/main/github-metrics.svg" alt="Metrics" />
</p>

## 🏆 Conquistas

<p align="center">
  <img src="https://raw.githubusercontent.com/segredounlock/segredounlock/main/github-conquistas.svg" alt="Conquistas do perfil" />
</p>

## 📊 Estatísticas

<p align="center">
  <img src="https://github-profile-summary-cards.vercel.app/api/cards/stats?username=segredounlock&theme=tokyonight" alt="Resumo geral do GitHub" />
  <img src="https://github-profile-summary-cards.vercel.app/api/cards/repos-per-language?username=segredounlock&theme=tokyonight" alt="Repositórios por linguagem" />
</p>

<p align="center">
  <img src="https://github-profile-summary-cards.vercel.app/api/cards/most-commit-language?username=segredounlock&theme=tokyonight" alt="Linguagem com mais commits" />
  <img src="https://streak-stats.demolab.com/?user=segredounlock&theme=tokyonight&hide_border=true&locale=pt_BR" alt="Sequência de contribuições" />
</p>

## 📈 Atividade

<p align="center">
  <img src="https://github-readme-activity-graph.vercel.app/graph?username=segredounlock&theme=tokyo-night&hide_border=true&area=true&custom_title=Atividade%20no%20GitHub" alt="Atividade no GitHub" />
</p>

---

<p align="center">
  <sub>
    <b>SEGREDO/CHEFE</b> define o objetivo · <b>SOL</b> coordena · <b>PIVETE/HERMES</b> executa e preserva<br/>
    GitHub registra · CI testa · Runtime prova · README não fabrica verde<br/>
    ☕ · PM2 · Caddy · PowerShell · <b>SegredoiDev</b> · CentralDark
  </sub>
</p>
