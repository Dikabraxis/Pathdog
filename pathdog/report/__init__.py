"""Report package — console / Markdown / HTML renderers for pathdog.

This package replaces the legacy single-file ``pathdog.report`` module. The
public renderer API used by the CLI is re-exported here.
"""

from .console import (
    print_findings_console,
    print_intermediate_targets,
    print_node_visibility_console,
    print_paths_console,
    print_pivot_candidates,
    print_quickwins,
)
from .html import (
    render_html,
    render_html_combined,
    render_html_multi,
    render_html_node_visibility,
)
from .markdown import (
    render_markdown,
    render_markdown_multi,
    render_markdown_node_visibility,
)

__all__ = [
    "print_findings_console",
    "print_intermediate_targets",
    "print_node_visibility_console",
    "print_paths_console",
    "print_pivot_candidates",
    "print_quickwins",
    "render_html",
    "render_html_combined",
    "render_html_multi",
    "render_html_node_visibility",
    "render_markdown",
    "render_markdown_multi",
    "render_markdown_node_visibility",
]
