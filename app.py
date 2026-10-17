
import re
from io import BytesIO

import nltk
from flask import Flask, request, render_template_string, send_file

app = Flask(__name__)

PATTERNS = {
    "Email Address": r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b",
    "Phone Number": r"(?<!\w)(?:\+?\d[\d\s()-]{7,}\d)(?!\w)",
    "Possible ID Number": r"(?<!\d)\d{12}(?!\d)"
}

WEIGHTS = {
    "Email Address": 30,
    "Phone Number": 25,
    "Possible ID Number": 35,
    "Person Name": 20,
    "Location": 15,
    "Organization": 10
}

HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PrivacyLens | Privacy Protection</title>
<style>
* { box-sizing:border-box; }
body { margin:0; font-family:Arial,sans-serif;
       background:#0b1020; color:#eef2ff; }
main { max-width:1050px; margin:auto; padding:32px 20px; }
header { display:flex; align-items:center; gap:14px; margin-bottom:30px; }
.logo { background:#7467f0; padding:13px; border-radius:14px; font-size:25px; }
h1 { margin:0; font-size:30px; }
.subtitle,.muted { color:#aab4d0; }
.subtitle { margin-top:7px; }
.muted { font-size:14px; }
.panel { background:#151d32; border:1px solid #283450;
         border-radius:16px; padding:24px; margin-bottom:20px; }
h2 { margin-top:0; font-size:20px; }
textarea { width:100%; min-height:175px; resize:vertical; padding:15px;
           border-radius:10px; border:1px solid #394866;
           background:#0d1426; color:#eef2ff; font-size:15px; line-height:1.6; }
button { display:inline-block; margin-top:14px; padding:12px 19px;
         background:#7467f0; color:white; border:0; border-radius:9px;
         font-size:15px; font-weight:bold; cursor:pointer; }
button:hover { background:#5d50d8; }
.metrics { display:grid; grid-template-columns:repeat(3,1fr); gap:14px; }
.metric { background:#0d1426; border:1px solid #283450;
          padding:18px; border-radius:12px; }
.metric strong { display:block; font-size:27px; margin-top:10px; }
.risk { color:#ffbd69; }
.safe { color:#6ee7b7; }
.finding { padding:13px; margin:10px 0; background:#252039;
           border-left:4px solid #ffbd69; border-radius:7px;
           overflow-wrap:anywhere; }
pre { white-space:pre-wrap; overflow-wrap:anywhere; line-height:1.6;
      background:#0d1426; border-radius:10px; padding:16px; }
.note { color:#aab4d0; font-size:13px; line-height:1.6; }
@media(max-width:650px) {
  .metrics { grid-template-columns:1fr; }
  main { padding:18px 12px; }
  .panel { padding:17px; }
}
</style>
</head>
<body>
<main>
<header>
  <div class="logo">🔐</div>
  <div>
    <h1>PrivacyLens</h1>
    <div class="subtitle">Detect. Understand. Protect.</div>
  </div>
</header>

<section class="panel">
  <h2>Scan your text</h2>
  <p class="muted">Check text for possible personal information before sharing it.</p>
  <form method="POST">
    <textarea name="text" required
      placeholder="Example: Contact Alex at demo@example.com.">{{ text }}</textarea>
    <button type="submit">Scan for Privacy Risks →</button>
  </form>
</section>

{% if scanned %}
<section class="panel">
  <h2>Scan Results</h2>
  <div class="metrics">
    <div class="metric">
      <span class="muted">Potential findings</span>
      <strong>{{ findings|length }}</strong>
    </div>
    <div class="metric">
      <span class="muted">Heuristic risk score</span>
      <strong class="{{ 'risk' if score >= 30 else 'safe' }}">{{ score }}/100</strong>
    </div>
    <div class="metric">
      <span class="muted">Risk level</span>
      <strong class="{{ 'risk' if score >= 30 else 'safe' }}">{{ level }}</strong>
    </div>
  </div>

  <h2 style="margin-top:24px">Detected information</h2>
  {% if findings %}
    {% for item in findings %}
      <div class="finding">
        <b>{{ item[0] }}</b><br>
        <span class="muted">Potential finding:</span> {{ item[1] }}
      </div>
    {% endfor %}
  {% else %}
    <p class="safe">No supported patterns or entities were detected.</p>
  {% endif %}

  {% if nlp_error %}
    <p class="note">NLP detection was unavailable for this scan.
    Pattern-based detection still ran. Check that the NLTK resources
    are installed on the server.</p>
  {% endif %}
</section>

<section class="panel">
  <h2>Protected text</h2>
  <p class="muted">Review this version before sharing it.</p>
  <pre>{{ protected }}</pre>
  <form method="POST" action="/download">
    <input type="hidden" name="protected" value="{{ protected }}">
    <button type="submit">Download Protected Text ↓</button>
  </form>
</section>
{% endif %}

<section class="panel">
  <h2>How PrivacyLens works</h2>
  <p class="note">
    Pattern matching checks for email addresses, possible phone numbers
    and possible 12-digit ID numbers. NLTK's pretrained named-entity
    recognizer looks for people, locations and organizations.
    Results can contain false positives and missed detections.
    The score is a simple demonstration heuristic, not a validated
    privacy assessment. Do not enter real confidential information.
  </p>
</section>
<p class="note">PrivacyLens · IBM Z Datathon 2026</p>
</main>
</body>
</html>
"""


def scan_text(text):
    # Each finding is (start, end, label, matched text).
    candidates = []

    # Pattern-based detection.
    for label, pattern in PATTERNS.items():
        for match in re.finditer(pattern, text):
            candidates.append(
                (match.start(), match.end(), label, match.group())
            )

    nlp_error = False

    # Pretrained NLTK named-entity recognition.
    try:
        tokens = nltk.word_tokenize(text)
        tagged = nltk.pos_tag(tokens)
        tree = nltk.ne_chunk(tagged)

        # Locate tokens in the original text to preserve exact offsets.
        token_spans = []
        cursor = 0
        for token in tokens:
            start = text.find(token, cursor)
            if start == -1:
                token_spans.append(None)
                continue
            end = start + len(token)
            token_spans.append((start, end))
            cursor = end

        token_index = 0
        for node in tree:
            if hasattr(node, "label"):
                label_map = {
                    "PERSON": "Person Name",
                    "GPE": "Location",
                    "LOCATION": "Location",
                    "FACILITY": "Location",
                    "ORGANIZATION": "Organization"
                }

                entity_label = label_map.get(node.label())
                leaves = node.leaves()
                count = len(leaves)
                spans = token_spans[token_index:token_index + count]

                if entity_label and spans and all(spans):
                    start = spans[0][0]
                    end = spans[-1][1]
                    value = text[start:end]

                    # Ignore common words incorrectly included in names.
                    if entity_label == "Person Name":
                        first_word = value.split()[0].lower()
                        if first_word in {
                            "contact", "email", "call", "reach",
                            "visit", "visited", "meet", "send"
                        }:
                            token_index += count
                            continue

                    candidates.append(
                        (start, end, entity_label, value)
                    )

                token_index += count
            else:
                token_index += 1

    except (LookupError, ValueError, ImportError):
        nlp_error = True
    # Merge adjacent parts of a person's name.
    candidates.sort(key=lambda x: x[0])

    merged = []
    for item in candidates:
        if (
            merged
            and item[2] == "Person Name"
            and merged[-1][2] == "Person Name"
            and text[merged[-1][1]:item[0]].isspace()
        ):
            previous = merged.pop()
            merged.append((
                previous[0],
                item[1],
                "Person Name",
                text[previous[0]:item[1]]
            ))
        else:
            merged.append(item)

    candidates = merged
    # Resolve overlapping detections, preferring the longest match
    # when two candidates start at the same position.
    candidates.sort(key=lambda x: (x[0], -(x[1] - x[0])))
    selected = []
    last_end = -1

    for start, end, label, value in candidates:
        if start < last_end:
            continue
        selected.append((start, end, label, value))
        last_end = end

    findings = [(label, value) for _, _, label, value in selected]

    # Redact from right to left so original offsets remain valid.
    protected = text
    for start, end, label, value in reversed(selected):
        protected = (
            protected[:start]
            + f"[{label.upper()} REDACTED]"
            + protected[end:]
        )

    # Count each information category only once.
    unique_weights = {
        label: WEIGHTS.get(label, 0)
        for label, value in findings
    }

    weights = sorted(unique_weights.values(), reverse=True)

    # Highest-risk category counts fully; others count half.
    score = (
        0 if not weights
        else min(100, round(weights[0] + 0.5 * sum(weights[1:])))
    )
    if score >= 60:
        level = "High"
    elif score >= 30:
        level = "Medium"
    else:
        level = "Low"

    return findings, protected, score, level, nlp_error


@app.route("/", methods=["GET", "POST"])
def home():
    scanned = request.method == "POST"
    text = request.form.get("text", "") if scanned else ""

    if scanned:
        findings, protected, score, level, nlp_error = scan_text(text)
    else:
        findings, protected, score, level, nlp_error = [], "", 0, "Not scanned", False

    return render_template_string(
        HTML,
        text=text,
        scanned=scanned,
        findings=findings,
        protected=protected,
        score=score,
        level=level,
        nlp_error=nlp_error
    )


@app.route("/download", methods=["POST"])
def download():
    protected = request.form.get("protected", "")
    return send_file(
        BytesIO(protected.encode("utf-8")),
        mimetype="text/plain",
        as_attachment=True,
        download_name="protected_text.txt"
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8501, debug=False)
