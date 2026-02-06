#!/usr/bin/env python3
"""
Build the vendored GDPR bundled JSON data file.

Fetches all 99 GDPR articles + 173 recitals + Article 4 definitions from
https://gdpr-info.eu (a well-known structured reference maintained by
intersoft consulting services AG) and assembles them into the JSON schema
expected by data_loader.py.

Usage:
    python scripts/build_gdpr_data.py

Output:
    src/gdpr_shift_left_mcp/data/gdpr_bundled.json
"""

import json
import re
import sys
import time
from pathlib import Path

import httpx
from bs4 import BeautifulSoup

BASE = "https://gdpr-info.eu"
OUTPUT = Path(__file__).resolve().parent.parent / "src" / "gdpr_shift_left_mcp" / "data" / "gdpr_bundled.json"

# GDPR structure: 11 chapters, 99 articles
CHAPTERS = [
    {"number": 1, "title": "General provisions", "articles": list(range(1, 5))},
    {"number": 2, "title": "Principles", "articles": list(range(5, 12))},
    {"number": 3, "title": "Rights of the data subject", "articles": list(range(12, 24))},
    {"number": 4, "title": "Controller and processor", "articles": list(range(24, 44))},
    {"number": 5, "title": "Transfers of personal data to third countries or international organisations", "articles": list(range(44, 50))},
    {"number": 6, "title": "Independent supervisory authorities", "articles": list(range(51, 60))},  # 51-59
    {"number": 7, "title": "Cooperation and consistency", "articles": list(range(60, 77))},
    {"number": 8, "title": "Remedies, liability and penalties", "articles": list(range(77, 85))},
    {"number": 9, "title": "Provisions relating to specific processing situations", "articles": list(range(85, 92))},
    {"number": 10, "title": "Delegated acts and implementing acts", "articles": list(range(92, 94))},
    {"number": 11, "title": "Final provisions", "articles": list(range(94, 100))},
]

# Chapter 6 actually goes 51-59 but article 50 is in chapter 5
# Let me adjust: Chapter 5 is 44-50 (inclusive), Chapter 6 is 51-59
# Fixing chapter 5:
CHAPTERS[4]["articles"] = list(range(44, 51))  # 44-50
CHAPTERS[5]["articles"] = list(range(51, 60))  # 51-59


def fetch_page(url: str, retries: int = 3) -> str:
    """Fetch a page with retries and rate limiting."""
    for attempt in range(retries):
        try:
            with httpx.Client(timeout=30, follow_redirects=True) as client:
                resp = client.get(url, headers={"User-Agent": "GDPRShiftLeftMCP-DataBuilder/0.1"})
                resp.raise_for_status()
                return resp.text
        except Exception as exc:
            if attempt < retries - 1:
                wait = 2 ** attempt
                print(f"  Retry {attempt + 1} after error: {exc} (waiting {wait}s)")
                time.sleep(wait)
            else:
                raise
    return ""


def extract_article_text(html: str) -> dict:
    """Extract article title and text from a gdpr-info.eu article page."""
    soup = BeautifulSoup(html, "lxml")

    # Title is in h1, format: "Art. N GDPRTitle Text"
    h1 = soup.find("h1")
    full_title = h1.get_text(strip=True) if h1 else ""

    # Extract title after "GDPR" prefix
    title = ""
    if "GDPR" in full_title:
        title = full_title.split("GDPR", 1)[1].strip()
    else:
        title = full_title

    # The article content is in the .entry-content div
    content_div = soup.find("div", class_="entry-content")
    if not content_div:
        return {"title": title, "text": "", "paragraphs": []}

    # Remove the "Suitable Recitals" section and everything after
    for h2 in content_div.find_all("h2"):
        if "Suitable Recitals" in h2.get_text():
            # Remove this h2 and all following siblings
            for sibling in list(h2.find_next_siblings()):
                sibling.decompose()
            h2.decompose()
            break

    # Remove any remaining nav/footer elements
    for tag in content_div.find_all(["nav", "footer", "aside", "script", "style"]):
        tag.decompose()

    # Get clean text
    text = content_div.get_text(separator="\n", strip=True)

    # Try to extract numbered paragraphs
    paragraphs = []
    # Pattern: "1." or "1.Text" at start of line
    lines = text.split("\n")
    current_para = []
    current_num = None

    for line in lines:
        line = line.strip()
        if not line:
            continue
        # Check if line starts with a paragraph number like "1." or "1.Text"
        m = re.match(r'^(\d+)\.\s*(.*)', line)
        if m and int(m.group(1)) == (current_num or 0) + 1:
            # Save previous paragraph
            if current_num is not None:
                paragraphs.append({
                    "number": current_num,
                    "text": " ".join(current_para).strip()
                })
            current_num = int(m.group(1))
            current_para = [m.group(2)] if m.group(2) else []
        else:
            current_para.append(line)

    if current_num is not None:
        paragraphs.append({
            "number": current_num,
            "text": " ".join(current_para).strip()
        })

    return {"title": title, "text": text, "paragraphs": paragraphs}


def extract_recital_text(html: str) -> dict:
    """Extract recital number and text from a gdpr-info.eu recital page."""
    soup = BeautifulSoup(html, "lxml")

    h1 = soup.find("h1")
    full_title = h1.get_text(strip=True) if h1 else ""

    # Title format: "Recital N EU GDPRTitle"
    title = ""
    if "GDPR" in full_title:
        title = full_title.split("GDPR", 1)[1].strip()

    content_div = soup.find("div", class_="entry-content")
    if not content_div:
        return {"title": title, "text": ""}

    # Remove nav elements
    for tag in content_div.find_all(["nav", "footer", "aside", "script", "style", "h2"]):
        tag.decompose()

    text = content_div.get_text(separator=" ", strip=True)
    # Clean up excessive whitespace
    text = re.sub(r'\s+', ' ', text).strip()

    return {"title": title, "text": text}


def build_articles() -> dict:
    """Fetch all 99 GDPR articles and organize by chapter."""
    all_articles = {}
    chapters_data = []

    for chapter in CHAPTERS:
        chapter_articles = []
        print(f"\nChapter {chapter['number']}: {chapter['title']}")

        for art_num in chapter["articles"]:
            url = f"{BASE}/art-{art_num}-gdpr/"
            print(f"  Fetching Article {art_num}...", end=" ", flush=True)

            try:
                html = fetch_page(url)
                art_data = extract_article_text(html)
                article = {
                    "number": art_num,
                    "title": art_data["title"],
                    "text": art_data["text"],
                    "paragraphs": art_data["paragraphs"],
                }
                chapter_articles.append(article)
                all_articles[str(art_num)] = article
                print(f"OK ({len(art_data['text'])} chars)")
            except Exception as exc:
                print(f"FAILED: {exc}")
                chapter_articles.append({
                    "number": art_num,
                    "title": f"Article {art_num}",
                    "text": "",
                    "paragraphs": [],
                })

            time.sleep(0.5)  # Be polite

        chapters_data.append({
            "number": chapter["number"],
            "title": chapter["title"],
            "articles": chapter_articles,
        })

    return {"chapters": chapters_data, "all_articles": all_articles}


def build_recitals() -> list:
    """Fetch all 173 GDPR recitals."""
    recitals = []

    print("\n\nFetching recitals...")
    for n in range(1, 174):
        url = f"{BASE}/recitals/no-{n}/"
        print(f"  Recital {n}...", end=" ", flush=True)

        try:
            html = fetch_page(url)
            rec_data = extract_recital_text(html)
            recitals.append({
                "number": n,
                "title": rec_data["title"],
                "text": rec_data["text"],
            })
            print(f"OK ({len(rec_data['text'])} chars)")
        except Exception as exc:
            print(f"FAILED: {exc}")
            recitals.append({
                "number": n,
                "title": "",
                "text": "",
            })

        time.sleep(0.5)

    return recitals


def build_definitions(all_articles: dict) -> list:
    """Extract Article 4 definitions."""
    # Article 4 contains 26 numbered definitions
    # We'll parse them from the article text or provide curated versions
    definitions = [
        {"term": "Personal data", "definition": "any information relating to an identified or identifiable natural person ('data subject'); an identifiable natural person is one who can be identified, directly or indirectly, in particular by reference to an identifier such as a name, an identification number, location data, an online identifier or to one or more factors specific to the physical, physiological, genetic, mental, economic, cultural or social identity of that natural person", "article_reference": "Article 4(1)"},
        {"term": "Processing", "definition": "any operation or set of operations which is performed on personal data or on sets of personal data, whether or not by automated means, such as collection, recording, organisation, structuring, storage, adaptation or alteration, retrieval, consultation, use, disclosure by transmission, dissemination or otherwise making available, alignment or combination, restriction, erasure or destruction", "article_reference": "Article 4(2)"},
        {"term": "Restriction of processing", "definition": "the marking of stored personal data with the aim of limiting their processing in the future", "article_reference": "Article 4(3)"},
        {"term": "Profiling", "definition": "any form of automated processing of personal data consisting of the use of personal data to evaluate certain personal aspects relating to a natural person, in particular to analyse or predict aspects concerning that natural person's performance at work, economic situation, health, personal preferences, interests, reliability, behaviour, location or movements", "article_reference": "Article 4(4)"},
        {"term": "Pseudonymisation", "definition": "the processing of personal data in such a manner that the personal data can no longer be attributed to a specific data subject without the use of additional information, provided that such additional information is kept separately and is subject to technical and organisational measures to ensure that the personal data are not attributed to an identified or identifiable natural person", "article_reference": "Article 4(5)"},
        {"term": "Filing system", "definition": "any structured set of personal data which are accessible according to specific criteria, whether centralised, decentralised or dispersed on a functional or geographical basis", "article_reference": "Article 4(6)"},
        {"term": "Controller", "definition": "the natural or legal person, public authority, agency or other body which, alone or jointly with others, determines the purposes and means of the processing of personal data; where the purposes and means of such processing are determined by Union or Member State law, the controller or the specific criteria for its nomination may be provided for by Union or Member State law", "article_reference": "Article 4(7)"},
        {"term": "Processor", "definition": "a natural or legal person, public authority, agency or other body which processes personal data on behalf of the controller", "article_reference": "Article 4(8)"},
        {"term": "Recipient", "definition": "a natural or legal person, public authority, agency or another body, to which the personal data are disclosed, whether a third party or not. However, public authorities which may receive personal data in the framework of a particular inquiry in accordance with Union or Member State law shall not be regarded as recipients; the processing of those data by those public authorities shall be in compliance with the applicable data protection rules according to the purposes of the processing", "article_reference": "Article 4(9)"},
        {"term": "Third party", "definition": "a natural or legal person, public authority, agency or body other than the data subject, controller, processor and persons who, under the direct authority of the controller or processor, are authorised to process personal data", "article_reference": "Article 4(10)"},
        {"term": "Consent", "definition": "any freely given, specific, informed and unambiguous indication of the data subject's wishes by which he or she, by a statement or by a clear affirmative action, signifies agreement to the processing of personal data relating to him or her", "article_reference": "Article 4(11)"},
        {"term": "Personal data breach", "definition": "a breach of security leading to the accidental or unlawful destruction, loss, alteration, unauthorised disclosure of, or access to, personal data transmitted, stored or otherwise processed", "article_reference": "Article 4(12)"},
        {"term": "Genetic data", "definition": "personal data relating to the inherited or acquired genetic characteristics of a natural person which give unique information about the physiology or the health of that natural person and which result, in particular, from an analysis of a biological sample from the natural person in question", "article_reference": "Article 4(13)"},
        {"term": "Biometric data", "definition": "personal data resulting from specific technical processing relating to the physical, physiological or behavioural characteristics of a natural person, which allow or confirm the unique identification of that natural person, such as facial images or dactyloscopic data", "article_reference": "Article 4(14)"},
        {"term": "Data concerning health", "definition": "personal data related to the physical or mental health of a natural person, including the provision of health care services, which reveal information about his or her health status", "article_reference": "Article 4(15)"},
        {"term": "Main establishment", "definition": "as regards a controller with establishments in more than one Member State, the place of its central administration in the Union, unless the decisions on the purposes and means of the processing of personal data are taken in another establishment of the controller in the Union and the latter establishment has the power to have such decisions implemented, in which case the establishment having taken such decisions is to be considered to be the main establishment; as regards a processor with establishments in more than one Member State, the place of its central administration in the Union, or, if the processor has no central administration in the Union, the establishment of the processor in the Union where the main processing activities in the context of the activities of an establishment of the processor take place to the extent that the processor is subject to specific obligations under this Regulation", "article_reference": "Article 4(16)"},
        {"term": "Representative", "definition": "a natural or legal person established in the Union who, designated by the controller or processor in writing pursuant to Article 27, represents the controller or processor with regard to their respective obligations under this Regulation", "article_reference": "Article 4(17)"},
        {"term": "Enterprise", "definition": "a natural or legal person engaged in an economic activity, irrespective of its legal form, including partnerships or associations regularly engaged in an economic activity", "article_reference": "Article 4(18)"},
        {"term": "Group of undertakings", "definition": "a controlling undertaking and its controlled undertakings", "article_reference": "Article 4(19)"},
        {"term": "Binding corporate rules", "definition": "personal data protection policies which are adhered to by a controller or processor established on the territory of a Member State for transfers or a set of transfers of personal data to a controller or processor in one or more third countries within a group of undertakings, or group of enterprises engaged in a joint economic activity", "article_reference": "Article 4(20)"},
        {"term": "Supervisory authority", "definition": "an independent public authority which is established by a Member State pursuant to Article 51", "article_reference": "Article 4(21)"},
        {"term": "Supervisory authority concerned", "definition": "a supervisory authority which is concerned by the processing of personal data because: (a) the controller or processor is established on the territory of the Member State of that supervisory authority; (b) data subjects residing in the Member State of that supervisory authority are substantially affected or likely to be substantially affected by the processing; or (c) a complaint has been lodged with that supervisory authority", "article_reference": "Article 4(22)"},
        {"term": "Cross-border processing", "definition": "either (a) processing of personal data which takes place in the context of the activities of establishments in more than one Member State of a controller or processor in the Union where the controller or processor is established in more than one Member State; or (b) processing of personal data which takes place in the context of the activities of a single establishment of a controller or processor in the Union but which substantially affects or is likely to substantially affect data subjects in more than one Member State", "article_reference": "Article 4(23)"},
        {"term": "Relevant and reasoned objection", "definition": "an objection to a draft decision as to whether there is an infringement of this Regulation, or whether envisaged action in relation to the controller or processor complies with this Regulation, which clearly demonstrates the significance of the risks posed by the draft decision as regards the fundamental rights and freedoms of data subjects and, where applicable, the free flow of personal data within the Union", "article_reference": "Article 4(24)"},
        {"term": "Information society service", "definition": "a service as defined in point (b) of Article 1(1) of Directive (EU) 2015/1535 of the European Parliament and of the Council", "article_reference": "Article 4(25)"},
        {"term": "International organisation", "definition": "an organisation and its subordinate bodies governed by public international law, or any other body which is set up by, or on the basis of, an agreement between two or more countries", "article_reference": "Article 4(26)"},
    ]
    return definitions


def main():
    print("=" * 60)
    print("GDPR Bundled Data Builder")
    print("Source: https://gdpr-info.eu")
    print("=" * 60)

    # Build articles
    result = build_articles()
    chapters_data = result["chapters"]

    # Build recitals
    recitals = build_recitals()

    # Build definitions
    definitions = build_definitions(result["all_articles"])

    # Assemble final structure
    gdpr_data = {
        "_meta": {
            "source": "https://gdpr-info.eu",
            "regulation": "Regulation (EU) 2016/679 (General Data Protection Regulation)",
            "description": "Structured GDPR text for the GDPR Shift-Left MCP Server",
            "generated_by": "scripts/build_gdpr_data.py",
            "note": "EU regulations are public law and not subject to copyright restrictions",
        },
        "chapters": chapters_data,
        "recitals": recitals,
        "definitions": definitions,
    }

    # Write output
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(gdpr_data, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"\n{'=' * 60}")
    print(f"Output: {OUTPUT}")
    print(f"Articles: {sum(len(c['articles']) for c in chapters_data)}")
    print(f"Recitals: {len(recitals)}")
    print(f"Definitions: {len(definitions)}")
    print(f"File size: {OUTPUT.stat().st_size / 1024:.0f} KB")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
