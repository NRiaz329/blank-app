Build a complete production-ready Email Verification SaaS using ONLY free and open-source tools.

Requirements:

Tech Stack:

Python + FastAPI (async)

PostgreSQL

Redis + Celery

SQLAlchemy ORM

WebSocket support

React (Vite) frontend OR modern HTML/CSS/JS

Docker + docker-compose

Nginx reverse proxy

Ubuntu VPS compatible

Core Features:

Multi-layer Validation Engine

RFC 5322 syntax validation

DNS A record check

MX record validation

Disposable domain detection (use open-source GitHub list)

Role-based detection (admin, info, support, contact, sales, billing, help)

Deep SMTP validation using raw socket:

Connect to MX

EHLO

MAIL FROM

RCPT TO

Capture SMTP response codes

Timeout handling

Max 2 retries

Do NOT send actual email

Catch-all detection (test real + random email same domain)

AI Bounce Risk Scoring

Use heuristic scoring OR scikit-learn LogisticRegression

Features:

SMTP code

Response time

Catch-all flag

Disposable flag

Role-based flag

Free vs custom domain

Output:
{
email,
status (VALID, INVALID, RISKY, DISPOSABLE, CATCH_ALL),
risk_score (0–100),
confidence_score,
reason
}

Auto-train model if missing

Weekly retraining setup

Live Single Email Verification

Input field on frontend

Real-time progress steps:

Syntax

DNS

MX

SMTP

Risk scoring

Use WebSocket for live updates

5–15 sec completion target

Bulk Verification

CSV upload (up to 50k emails)

Async processing with Redis + Celery

Parallel workers

Export VALID/INVALID only

Rate Limiting

500 verifications per IP per 24h (free users)

Admin bypass unlimited

Admin Panel

Password protected

View stats (total, valid, invalid, risky)

View SMTP logs

View worker node health

Block abusive IPs

Distributed Worker Architecture

Main API server

Separate SMTP worker nodes

Redis task distribution

Randomize HELO

Random delay

Heartbeat monitoring

Auto-disable unhealthy worker

Security:

API key authentication

IP rate limiting

Input sanitization

CSV validation

Abuse prevention logic

Output Instructions:

Print full folder structure first

Then generate each file completely

No placeholders

No TODO comments

No pseudo-code

Must run with docker-compose up --build

Generate full project now.
