# AEGIS Desktop

Aplicativo antivírus do projeto AEGIS. Usa apenas a biblioteca padrão do Python 3.9+.

- Interface gráfica: `python aegis_app.py` (Windows: `run_windows.bat`; Linux/macOS: `./run_linux.sh`)
- Linha de comando: `python aegis_cli.py --help`
- Executável Windows: `build_exe.bat` (gera `dist\AEGIS.exe`)

O arquivo `config.json` define o endereço do servidor (o zip baixado pelo site já vem preenchido). Dados locais (assinaturas, quarentena, sessão) ficam em `~/.aegis`.

No app: **Painel → Criar arquivos de teste** gera o arquivo EICAR (inofensivo) para validar a detecção.

## ClamAV (opcional)

Com o [ClamAV](https://www.clamav.net/downloads) instalado, o app o detecta sozinho (daemon `clamd` ou executável `clamscan`) e o usa como primeira camada de detecção. Veja **Conta e ajustes → ClamAV** ou `python aegis_cli.py clamav status`. Detalhes de instalação no README da raiz do projeto.
