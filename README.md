# CS411 Project 1 — Ollama

Software architecture analysis of [Ollama](https://github.com/ollama/ollama), an observability
extension, and a new login page with an IAM module (Ollama Gateway).

| Folder | Contents |
|---|---|
| `report/` | Final report PDF (`CS411_Project1_Ollama_Report.pdf`), its HTML source, UML diagrams (PlantUML sources + PNG) and screenshots |
| `ollama-gateway/` | Part 4 implementation: FastAPI login, sign-up with email confirmation, roles and model access, audit log. See its README to run it. |

Presentation slides: shared separately as a link.

## Quick start (Ollama Gateway)

```bash
cd ollama-gateway
pip install -r requirements.txt
ollama serve            # or: python mock_ollama.py
python run_gateway.py   # http://127.0.0.1:8000
```

Email sign-up needs SMTP settings; see `ollama-gateway/README.md`. Never commit passwords.

## Group members

| Name | Student ID |
|---|---|
|Shahin Ibrahimli | 22301574 |
| Farrukh Mammadov | 22301186 |
| Leyla Abbasova | 22301172 |
| Zaeem Sheikh Masood | 22201178 |
