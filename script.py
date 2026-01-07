import requests
import argparse
import json
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import re

# -------------------------------
# Конфигурация
# -------------------------------

TIMEOUT = 10

COMMON_PATHS = [
    "/admin", "/login", "/dashboard", "/config", "/wp-admin"
]

SENSITIVE_FILES = [
    "/.git/HEAD",
    "/.env",
    "/.DS_Store"
]

SEVERITY_SCORES = {
    "LOW": 2,
    "MEDIUM": 5,
    "HIGH": 10
}

SECURITY_HEADERS = {
    "content-security-policy": ("A02 Cryptographic Failures", "MEDIUM"),
    "x-content-type-options": ("A02 Cryptographic Failures", "LOW"),
    "x-frame-options": ("A02 Cryptographic Failures", "MEDIUM"),
    "referrer-policy": ("A02 Cryptographic Failures", "LOW")
}

SSRF_PARAMS = ["url", "redirect", "next", "callback", "return"]

# SQL Injection (пассивные индикаторы)
SQL_ERROR_PATTERNS = [
    "sql syntax",
    "mysql",
    "ora-",
    "odbc",
    "postgresql",
    "sqlite",
    "syntax error",
    "unclosed quotation",
    "unterminated string"
]

SQL_PARAM_NAMES = [
    "id", "user", "userid", "username",
    "query", "search", "filter", "item", "page"
]

# -------------------------------
# Валидация URL
# -------------------------------

def validate_url(url: str):
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("Некорректный URL. Пример: http://127.0.0.1:5000")

# -------------------------------
# Основной сканер
# -------------------------------

def scan(url: str) -> dict:
    validate_url(url)

    report = {
        "target": url,
        "issues": [],
        "score": {"total": 0, "level": "LOW"}
    }

    def add_issue(owasp, severity, description):
        score = SEVERITY_SCORES[severity]
        report["issues"].append({
            "owasp": owasp,
            "severity": severity,
            "score": score,
            "description": description
        })
        report["score"]["total"] += score

    try:
        r = requests.get(url, timeout=TIMEOUT)
    except Exception as e:
        report["error"] = str(e)
        return report

    headers = {k.lower(): v for k, v in r.headers.items()}
    body = r.text.lower()
    soup = BeautifulSoup(r.text, "html.parser")

    # ---------------- A02: Cryptographic Failures ----------------
    if not url.startswith("https://"):
        add_issue("A02 Cryptographic Failures", "HIGH", "Сайт не использует HTTPS")

    if "strict-transport-security" not in headers:
        add_issue("A02 Cryptographic Failures", "MEDIUM", "Отсутствует HSTS")

    for h, (owasp, sev) in SECURITY_HEADERS.items():
        if h not in headers:
            add_issue(owasp, sev, f"Отсутствует заголовок {h}")

    # ---------------- A05: Security Misconfiguration ----------------
    if "server" in headers:
        add_issue("A05 Security Misconfiguration", "LOW",
                  f"Раскрывается Server header: {headers['server']}")

    if "index of /" in body:
        add_issue("A05 Security Misconfiguration", "MEDIUM",
                  "Возможен directory listing")

    for path in SENSITIVE_FILES:
        try:
            resp = requests.head(urljoin(url, path), timeout=5)
            if resp.status_code < 400:
                add_issue("A05 Security Misconfiguration", "HIGH",
                          f"Доступен чувствительный файл: {path}")
        except:
            pass

    # ---------------- A01: Broken Access Control ----------------
    for path in COMMON_PATHS:
        try:
            resp = requests.head(urljoin(url, path), timeout=5)
            if resp.status_code < 400:
                add_issue("A01 Broken Access Control", "HIGH",
                          f"Публично доступный путь: {path}")
        except:
            pass

    # ---------------- A07: Identification and Authentication Failures ----------------
    for c in r.cookies:
        if not c.secure or not c.has_nonstandard_attr("HttpOnly"):
            add_issue("A07 Identification and Authentication Failures", "MEDIUM",
                      f"Cookie '{c.name}' без Secure/HttpOnly")

    # ---------------- A03: Injection (общие индикаторы) ----------------
    for form in soup.find_all("form"):
        method = form.get("method", "get").lower()
        if method == "get":
            add_issue("A03 Injection (indicator)", "LOW",
                      "Форма использует GET для передачи данных")

        if not form.find("input", {"name": re.compile("csrf", re.I)}):
            add_issue("A03 Injection (indicator)", "LOW",
                      "Форма без CSRF-токена")

        # SQL-чувствительные поля
        for inp in form.find_all("input"):
            name = (inp.get("name") or "").lower()
            if name in SQL_PARAM_NAMES:
                add_issue("A03 Injection (SQL indicator)", "MEDIUM",
                          f"Форма содержит SQL-чувствительное поле: '{name}'")

            if name in SSRF_PARAMS:
                add_issue("A10 SSRF (indicator)", "MEDIUM",
                          f"Форма содержит параметр '{name}'")

    # ---------------- A03: Injection (SQL) — пассивно ----------------
    # 1) SQL-ошибки в ответе
    for pattern in SQL_ERROR_PATTERNS:
        if pattern in body:
            add_issue("A03 Injection (SQL)", "HIGH",
                      f"В ответе обнаружено SQL-сообщение об ошибке: '{pattern}'")
            break

    # 2) SQL-параметры в URL
    parsed = urlparse(url)
    query = parsed.query.lower()
    for param in SQL_PARAM_NAMES:
        if param in query:
            add_issue("A03 Injection (SQL indicator)", "MEDIUM",
                      f"URL содержит потенциально SQL-чувствительный параметр: '{param}'")

    # ---------------- A06: Vulnerable & Outdated Components ----------------
    generator = soup.find("meta", {"name": "generator"})
    if generator and "wordpress" in (generator.get("content") or "").lower():
        add_issue("A06 Vulnerable Components", "MEDIUM",
                  f"Обнаружен WordPress: {generator.get('content')}")

    # ---------------- A08: Software & Data Integrity Failures ----------------
    for script in soup.find_all("script", src=True):
        if "integrity" not in script.attrs:
            add_issue("A08 Software Integrity Failures", "LOW",
                      f"Script без SRI (integrity): {script['src']}")

    # ---------------- Итоговый риск ----------------
    total = report["score"]["total"]
    report["score"]["level"] = (
        "CRITICAL" if total >= 50 else
        "HIGH" if total >= 25 else
        "MEDIUM" if total >= 10 else
        "LOW"
    )

    return report

# -------------------------------
# CLI
# -------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Этичный пассивный сканер веб-уязвимостей (OWASP Top 10)"
    )
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="URL цели (например: http://127.0.0.1:5000)"
    )

    args = parser.parse_args()
    print(json.dumps(scan(args.target), indent=2, ensure_ascii=False))
