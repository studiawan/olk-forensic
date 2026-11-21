# Sphinx configuration for the olk_forensic documentation.
# Build locally:  pip install -r docs/requirements.txt && sphinx-build -W -b html docs docs/_build/html
import os
import sys

sys.dont_write_bytecode = True
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "tools"))
sys.path.insert(0, ROOT)                                       # olk_forensic.py, hfl_parse.py
sys.path.insert(0, os.path.join(ROOT, "hxstore-decode", "src"))

# -- Project information ---------------------------------------------------------------
project = "olk_forensic"
author = "olk_forensic authors"            # TODO: replace with the author names
copyright = "2026, " + author
release = "1.0"
version = "1.0"

# -- General configuration -------------------------------------------------------------
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx.ext.mathjax",
    "sphinx.ext.todo",
]
templates_path = []
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]
root_doc = "index"
language = "en"
pygments_style = "sphinx"
todo_include_todos = False
numfig = True

# autodoc: the tool degrades gracefully if hxstore-decode cannot be imported, so importing
# it on the documentation server is safe; nothing is executed beyond module import.
autodoc_member_order = "bysource"
autodoc_default_options = {"undoc-members": False, "show-inheritance": False}
autodoc_mock_imports = ["lz4"]

# -- HTML output -----------------------------------------------------------------------
html_theme = "sphinx_rtd_theme"
html_title = "olk_forensic documentation"
html_short_title = "olk_forensic"
html_static_path = ["_static"]
html_theme_options = {
    "navigation_depth": 3,
    "collapse_navigation": False,
    "style_external_links": True,
}
html_show_sourcelink = True

# -- LaTeX / PDF output (Read the Docs "formats: pdf") -----------------------------------
latex_documents = [(root_doc, "olk_forensic.tex", "olk\\_forensic Documentation", author, "manual")]
latex_elements = {"papersize": "a4paper", "pointsize": "10pt"}

# -- EPUB ------------------------------------------------------------------------------
epub_show_urls = "footnote"
