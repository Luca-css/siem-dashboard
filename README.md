# SIEM Dashboard

Dashboard de segurança em tempo real para ambientes Windows. Agrega eventos de segurança de múltiplos servidores, detecta ataques de brute force automaticamente e exibe alertas ativos em interface web responsiva.

![Python](https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-000000?style=flat&logo=flask&logoColor=white)
![Security](https://img.shields.io/badge/SIEM-Security-00d4ff?style=flat&logo=shield&logoColor=white)
![Windows](https://img.shields.io/badge/Windows_Server-0078D6?style=flat&logo=windows&logoColor=white)

## Funcionalidades

- Coleta contínua de eventos do Security Event Log (a cada 30s)
- Detecção automática de brute force por IP e por usuário
- Painel com contadores em tempo real (logins, falhas, bloqueios)
- Feed de eventos recentes com categorização visual
- Sistema de alertas com histórico
- API REST para integração com outros sistemas
- Suporte a múltiplos servidores (expansível via configuração)

## Eventos Monitorados

| ID | Evento | Criticidade |
|----|--------|-------------|
| 4624 | Login bem-sucedido | Info |
| 4625 | Falha de login | Alta |
| 4648 | Login com credenciais explícitas | Média |
| 4672 | Privilégios especiais atribuídos | Média |
| 4720/4726 | Conta criada / excluída | Info / Alta |
| 4740/4767 | Conta bloqueada / desbloqueada | Alta / Info |

## Uso

```bash
pip install flask
python app.py
# Dashboard: http://localhost:5001
# API:       http://localhost:5001/api/stats
```

## Requisitos

- Python 3.8+
- Flask 2.x
- Windows com acesso ao Security Event Log (Admin)
