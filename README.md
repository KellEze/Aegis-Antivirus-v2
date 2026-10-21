# AEGIS — Next-Gen Security

Sistema completo de antivírus educacional, em duas partes que conversam entre si:

| Parte | O que é | Tecnologia |
|---|---|---|
| `server/` | Site de vendas, cadastro/login, painel do cliente, checkout (simulado), licenças e API | Python, Flask, SQLite |
| `desktop/` | **Aplicativo antivírus**: verificação, quarentena, tempo real, atualização de assinaturas | Python, Tkinter (somente biblioteca padrão) |
| `tests/` | 55 testes automatizados (site, API, motor, quarentena, tempo real, ClamAV e integração app ↔ servidor) | unittest |

## Como rodar o site

```bash
cd server
python -m venv .venv
# Windows: .venv\Scripts\activate      Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Abra **http://127.0.0.1:5000**. O banco (`instance/aegis.db`) e a chave secreta (`instance/secret.key`) são criados automaticamente na primeira execução.

Variáveis de ambiente opcionais: `AEGIS_PORT`, `AEGIS_HOST`, `AEGIS_DEBUG=1`, `AEGIS_SECRET_KEY`, `AEGIS_PUBLIC_URL` (endereço público, usado no zip do app), `AEGIS_HTTPS=1` (cookie seguro quando houver HTTPS).

## Como rodar o aplicativo

**Pelo site (recomendado):** crie uma conta, abra **Baixar o app**, baixe o zip (já vem apontando para o seu servidor) e execute `run_windows.bat` (Windows) ou `./run_linux.sh` (Linux/macOS).

**Direto da pasta do projeto:**

```bash
cd desktop
python aegis_app.py        # interface gráfica
python aegis_cli.py --help # linha de comando
```

No Linux, o Tkinter pode precisar de: `sudo apt install python3-tk`.

**Gerar o .exe (Windows):** `desktop\build_exe.bat` → `desktop\dist\AEGIS.exe`.

## Publicar no Render

O repositório já tem o `render.yaml`. **A raiz do repositório no GitHub deve ser esta pasta** (com `server/`, `desktop/` e `render.yaml` na raiz): o site gera o zip do aplicativo a partir da pasta `desktop/`.

1. Suba o projeto para o GitHub.
2. No Render: **New → Blueprint**, escolha o repositório e confirme. (Ou **New → Web Service** manual: *Build Command* `pip install -r server/requirements.txt`, *Start Command* `cd server && python app.py`, *Health Check Path* `/api/health`.)
3. Variáveis de ambiente (o Blueprint já cria as três primeiras):

| Variável | Para quê |
|---|---|
| `AEGIS_SECRET_KEY` | assina sessões e tokens do app (use valor longo e fixo; sem ela, logins caem a cada reinício) |
| `AEGIS_HTTPS=1` | cookies só em HTTPS |
| `AEGIS_BEHIND_PROXY=1` | o Render termina o HTTPS na frente do app: sem isso o zip do app apontaria para `http://` |
| `AEGIS_DEMO_EMAIL`, `AEGIS_DEMO_PASSWORD` (opcional) | recria uma conta de demonstração a cada partida |
| `AEGIS_DEMO_PLAN` (opcional) | `essencial`, `plus` ou `pro` (padrão `plus`) |
| `AEGIS_DB` (com disco) | caminho do banco no disco persistente, ex.: `/var/data/aegis.db` |

4. Depois do deploy, abra a URL `https://SEU-SERVICO.onrender.com`. O zip baixado já vem apontando para essa URL.

**Atenção ao plano gratuito (conferido na documentação do Render):**
- O serviço **dorme após 15 minutos** sem acessos e leva até ~1 minuto para acordar (o app desktop espera até 75 s no login).
- O sistema de arquivos é **efêmero**: o banco SQLite (contas, licenças, compras, histórico) é **apagado** a cada reinício, redeploy ou soneca. Para apresentações, use `AEGIS_DEMO_EMAIL`/`AEGIS_DEMO_PASSWORD`: a conta de demonstração é recriada sozinha.
- Para **manter os dados**, use um plano pago com **disco persistente** (descomente o bloco `disk:` do `render.yaml` e defina `AEGIS_DB`). Consulte os preços atuais em render.com/pricing. Outra saída é migrar para o Postgres do Render (exigiria adaptar as consultas SQL).

## Teste rápido de ponta a ponta (5 minutos)

1. Suba o site e **crie uma conta** (plano Essencial, grátis).
2. Em **Baixar o app**, baixe e abra o aplicativo; entre com e-mail e senha (ou a chave de licença).
3. No app, **Painel → Criar arquivos de teste**. Responda "Sim" para verificar a pasta.
4. O arquivo `eicar_test.txt` é detectado e **movido para a quarentena**. O `aegis_update_test.txt` **não** é detectado ainda.
5. Clique em **Atualizar assinaturas** e verifique de novo: agora o segundo arquivo também é detectado — a atualização realmente muda o que o app enxerga.
6. No site, **Minha área → Histórico**: a verificação e as ameaças aparecem.
7. Na aba **Proteção** do app, o tempo real está bloqueado. No site, assine o **Plus** (cartão de teste `4242 4242 4242 4242`), volte ao app (ele atualiza o plano sozinho ao abrir) e ative a proteção: coloque um arquivo EICAR na pasta Downloads e veja a detecção automática.

> O EICAR é um arquivo de teste inofensivo. Se o seu outro antivírus (ex.: Windows Defender) apagá-lo antes do AEGIS, é normal.

## O que o site faz

- Cadastro e login com senha em hash, **sessão**, proteção **CSRF**, limite de tentativas contra força bruta, cabeçalhos de segurança e CSP.
- **Checkout em nova aba** para os planos pagos, com validação (algoritmo de Luhn, validade, CVV). Pagamento **simulado**: guarda só bandeira e 4 últimos dígitos.
- Painel: visão geral, **chave de licença**, **dispositivos** (limite por plano), **histórico** de verificações e ameaças, compras, troca de senha, cancelamento de assinatura, exportação CSV (Pro).
- Assinaturas com validade de 30 dias; ao vencer, a conta volta sozinha ao Essencial.
- API para o aplicativo (`/api/auth/login`, `/api/me`, `/api/signatures`, `/api/scans`).

| Plano | Preço | Dispositivos | Tempo real | Histórico | CSV |
|---|---|---|---|---|---|
| Essencial | Grátis | 1 | — | 5 | — |
| Plus | R$ 19/mês | 3 | ✓ | 50 | — |
| Pro | R$ 39/mês | 10 | ✓ | 50 | ✓ |

## O que o aplicativo faz de verdade

- **Verificação rápida** (Downloads, Desktop, temporários) e **personalizada** (qualquer pasta).
- **Assinaturas SHA-256** e **padrões de bytes**, atualizáveis pelo servidor.
- **ClamAV opcional**: se instalado, é detectado sozinho e passa a ser a primeira camada de detecção (veja a seção "ClamAV" abaixo).
- **Heurística** com pontuação: dupla extensão enganosa (`fatura.pdf.exe`), executável disfarçado de imagem/documento, scripts com comandos codificados/de download, tentativa de apagar cópias de sombra ou desligar o Defender, entropia alta em executáveis, `autorun.inf`. 35+ pontos = suspeito; 70+ = malicioso.
- **Quarentena reversível**: o arquivo é codificado e isolado; dá para restaurar ou excluir.
- **Proteção em tempo real** (Plus/Pro): monitora pastas e verifica arquivos novos depois que terminam de chegar (varredura a cada 3 s).
- Envia o resultado ao painel online (apenas nome do arquivo, nunca o conteúdo ou o caminho).
- Funciona **offline** com as assinaturas já baixadas.

## ClamAV (detecção de malware real)

O AEGIS sozinho tem uma base pequena (EICAR + demonstração). Instalando o [ClamAV](https://www.clamav.net/downloads) o app passa a usar as milhões de assinaturas dele. Nada precisa ser configurado no código: o app detecta automaticamente.

| Modo | Como é detectado | Verificação | Tempo real |
|---|---|---|---|
| **clamd** (daemon) | socket Unix ou TCP `127.0.0.1:3310` | rápida: a base fica na memória | ✓ usa o ClamAV |
| **clamscan** | executável no PATH ou em `C:\Program Files\ClamAV` | uma execução por verificação; carregar a base leva de dezenas de segundos a minutos e usa bastante RAM | só o motor do AEGIS |

**Instalação**
- **Windows:** instale o ClamAV, copie `freshclam.conf.sample` para `freshclam.conf`, comente a linha `Example` e rode `freshclam.exe` para baixar a base.
- **Linux (Debian/Ubuntu):** `sudo apt install clamav clamav-daemon`, depois `sudo freshclam` e `sudo systemctl enable --now clamav-daemon`.
- **macOS:** `brew install clamav` e configure o freshclam.
- Os passos variam por versão: consulte https://docs.clamav.net/.

**No app:** *Conta e ajustes → ClamAV* tem **Detectar novamente**, **Testar ClamAV**, **Atualizar base de vírus** (roda o `freshclam`), caminho manual do `clamscan` e um interruptor. Na CLI: `python aegis_cli.py clamav status | test | update | on | off`.

**Como saber que o ClamAV realmente está trabalhando:** use **Testar ClamAV**. Ele passa o arquivo EICAR **somente** pelo ClamAV. Nas verificações, as detecções do ClamAV aparecem com o sufixo "(ClamAV)" e o motivo "Detectado pelo ClamAV".

Se o ClamAV falhar no meio (base ausente, daemon caiu), o AEGIS avisa e conclui a verificação só com o motor próprio.

## Limites (leia antes de apresentar)

- **É um projeto educacional.** Sem o ClamAV, a base inclui só o arquivo de teste EICAR e um de demonstração; **não** há base de malware real. Com o ClamAV a cobertura melhora muito, mas a heurística do AEGIS continua gerando falsos positivos/negativos e o conjunto **não substitui um antivírus comercial**. O site foi escrito de acordo (sem estatísticas ou promessas inventadas).
- **A integração com o ClamAV foi testada contra simulações fiéis** (um clamd falso que fala o protocolo real e um clamscan falso com o formato de saída real), pois não havia ClamAV no ambiente de desenvolvimento. Faça o teste real na sua máquina: **Testar ClamAV** deve dizer que o EICAR foi detectado.
- **Pagamento simulado.** Para cobrar de verdade, integre um gateway (Stripe, Mercado Pago…) no `comprar()` do `app.py`.
- **Tempo real por varredura periódica**, não por driver de kernel: não bloqueia a execução do arquivo antes de ele abrir.
- Para colocar online: use HTTPS (`AEGIS_HTTPS=1`), defina `AEGIS_SECRET_KEY`, rode atrás de um proxy e use um banco mais robusto se houver muitos usuários.
- A interface gráfica foi desenvolvida e revisada sem acesso a um desktop com Tkinter. Toda a lógica (motor, quarentena, API, tempo real, controlador) tem testes; a janela em si deve ser conferida visualmente na sua máquina.

## Testes

```bash
pip install -r server/requirements.txt
python -m unittest discover tests -v
```

## Estrutura

```
aegis-antivirus/
├── render.yaml           configuração do deploy no Render
├── server/
│   ├── app.py            rotas do site, painel, checkout e API
│   ├── database.py       SQLite (users, devices, compras, scans, detections)
│   ├── security.py       CSRF, rate limit, validações, Luhn
│   ├── signatures.json   base de assinaturas servida ao app
│   ├── templates/  static/
│   └── requirements.txt
├── desktop/
│   ├── aegis_app.py      interface gráfica (Tkinter)
│   ├── aegis_cli.py      linha de comando
│   ├── controller.py     lógica do app (compartilhada)
│   ├── engine.py         motor de detecção
│   ├── clam.py           integração com o ClamAV (clamd / clamscan)
│   ├── quarantine.py  realtime.py  api_client.py  config.py
│   └── run_*.{bat,sh}  build_exe.{bat,sh}  assets/
└── tests/
```
