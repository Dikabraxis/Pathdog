"""HTML head template (CSS + JS) used by all HTML renderers."""

_HTML_HEAD = """\
<!DOCTYPE html>
<html lang="en">
	<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Pathdog — {{TITLE_SUFFIX}}</title>
	<script>
	document.addEventListener("click", (event) => {
	  const button = event.target.closest(".copy-btn");
	  if (!button) return;
	  const box = button.closest(".cmd-box");
	  const pre = box ? box.querySelector("pre") : null;
	  if (!pre) return;
	  const done = () => {
	    const original = button.textContent;
	    button.textContent = "Copied";
	    window.setTimeout(() => { button.textContent = original; }, 1200);
	  };
	  if (navigator.clipboard) {
	    navigator.clipboard.writeText(pre.innerText).then(done);
	    return;
	  }
	  const range = document.createRange();
	  range.selectNodeContents(pre);
	  const selection = window.getSelection();
	  selection.removeAllRanges();
	  selection.addRange(range);
	  document.execCommand("copy");
	  selection.removeAllRanges();
	  done();
	});
	document.addEventListener("input", (event) => {
	  const input = event.target.closest(".object-filter");
	  if (!input) return;
	  const block = input.closest(".object-control-block");
	  if (!block) return;
	  const needle = input.value.trim().toLowerCase();
	  block.querySelectorAll("tr[data-filter]").forEach((row) => {
	    row.hidden = needle.length > 0 && !row.dataset.filter.includes(needle);
	  });
	});
	</script>
	<style>
  :root {
    --bg: #0d1117; --card: #161b22; --border: #30363d;
    --text: #e6edf3; --muted: #8b949e; --soft: #1c2128;
    --code-bg: #010409; --code-text: #e6edf3; --code-cmt: #6e7681;
    --primary: #58a6ff; --primary-soft: #1f3759;
    --success: #3fb950; --success-soft: #0f2e1a;
    --warn: #d29922; --warn-soft: #3d2e0a;
    --danger: #f85149; --danger-soft: #3d1417;
    --purple: #bc8cff; --purple-soft: #2d1a55;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  html { scroll-behavior: smooth; }
  body {
    background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    font-size: 14px; line-height: 1.55; padding: 2rem 1.5rem; max-width: 1100px;
    margin: 0 auto;
  }
  code, pre, .mono { font-family: "SF Mono", Menlo, Consolas, monospace; }
	  .title { color: var(--text); font-size: 1.05rem; margin-bottom: 1rem;
	           padding-bottom: .55rem; border-bottom: 1px solid var(--border); }
	  .title code { background: var(--soft); padding: .1rem .35rem;
	                border-radius: 3px; color: var(--primary); font-size: .85rem; }
	  .brand { font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
	  h2 { font-size: 1rem; color: var(--text); margin: 0 0 .5rem; }
  .sticky-nav { position: sticky; top: 0; z-index: 20; display: flex; gap: .35rem;
                overflow-x: auto; padding: .45rem 0 .75rem; margin-bottom: .5rem;
                background: var(--bg); border-bottom: 1px solid var(--border); }
  .sticky-nav a { flex: 0 0 auto; color: var(--muted); text-decoration: none;
                  border: 1px solid var(--border); background: var(--card);
                  border-radius: 999px; padding: .25rem .6rem; font-size: .75rem;
                  font-weight: 700; }
  .sticky-nav a:hover { color: var(--primary); border-color: var(--primary); }
  .more-section { background: var(--card); border: 1px solid var(--border);
                  border-radius: 6px; padding: .55rem .85rem; margin-bottom: .65rem; }
  .more-section > summary { cursor: pointer; list-style: none; color: var(--muted);
                            font-size: .85rem; font-weight: 600; user-select: none; }
  .more-section > summary::before { content: "▶ "; font-size: .65rem; }
  .more-section[open] > summary::before { content: "▼ "; }
  .more-section[open] > summary { color: var(--text); margin-bottom: .65rem;
                                  padding-bottom: .4rem; border-bottom: 1px solid var(--border); }

  /* VERDICT — one line, top of page */
  .verdict { display: flex; align-items: center; gap: .65rem;
             padding: .65rem 1rem; border-radius: 6px; margin-bottom: 1rem;
             background: var(--card); border: 1px solid var(--border); }
  .verdict-dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
  .verdict-win  .verdict-dot { background: var(--success); }
  .verdict-warn .verdict-dot { background: var(--warn); }
  .verdict-fail .verdict-dot { background: var(--danger); }
  .verdict-msg { font-size: .92rem; }
	  .verdict-msg b { color: var(--primary); }
	  .verdict-msg code { background: var(--soft); padding: .1rem .35rem; border-radius: 3px; }
  .badge-dcsync { background: var(--purple-soft); color: var(--purple);
                  border: 1px solid var(--purple); padding: .1rem .45rem;
                  border-radius: 10px; font-size: .68rem; font-weight: 700;
                  letter-spacing: .05em; margin-left: auto; }

	  /* SECTION */
  .report-section { background: var(--card); border: 1px solid var(--border);
                    border-radius: 10px; padding: 1.25rem 1.5rem; margin-bottom: 1.5rem; }
	  .section-lead { color: var(--muted); margin-bottom: 1rem; font-size: .9rem; }

	  /* ACTION PLAN */
	  .action-plan { background: var(--card); border: 1px solid var(--success);
	                 border-radius: 8px; margin-bottom: 1rem; overflow: hidden; }
	  .plan-head { display: flex; justify-content: space-between; align-items: flex-start;
	               gap: 1rem; padding: .85rem 1rem; background: var(--success-soft);
	               border-bottom: 1px solid var(--border); }
	  .eyebrow { color: var(--muted); font-size: .68rem; letter-spacing: .12em;
	             text-transform: uppercase; font-weight: 800; margin-bottom: .1rem; }
	  .plan-stats { display: flex; align-items: center; gap: .45rem; flex-wrap: wrap;
	                color: var(--muted); font-size: .78rem; justify-content: flex-end; }
	  .status-badge { border: 1px solid var(--border); border-radius: 10px;
	                  padding: .1rem .45rem; font-size: .68rem; font-weight: 800;
	                  letter-spacing: .06em; }
	  .status-exploitable { color: var(--success); border-color: var(--success);
	                        background: var(--success-soft); }
	  .status-pivot { color: var(--warn); border-color: var(--warn);
	                  background: var(--warn-soft); }
	  .status-fail { color: var(--danger); border-color: var(--danger);
	                 background: var(--danger-soft); }
	  .status-info { color: var(--primary); border-color: var(--primary);
	                 background: var(--primary-soft); }
	  .status-dcsync { color: var(--purple); border-color: var(--purple);
	                   background: var(--purple-soft); }
	  .plan-list { display: flex; flex-direction: column; }
	  .plan-row { display: flex; gap: .75rem; padding: .85rem 1rem;
	              border-top: 1px solid var(--border); }
	  .plan-row:first-child { border-top: none; }
	  .plan-num { width: 24px; height: 24px; border-radius: 50%; flex: 0 0 auto;
	              display: flex; align-items: center; justify-content: center;
	              background: var(--success); color: var(--bg); font-weight: 800;
	              font-size: .72rem; }
	  .plan-main { min-width: 0; flex: 1; }
	  .plan-title { font-weight: 700; margin-bottom: .2rem; }
	  .plan-meta, .plan-change { color: var(--muted); font-size: .78rem; }
	  .plan-meta code { background: var(--soft); color: var(--text);
	                    padding: .1rem .35rem; border-radius: 3px; }

	  /* KIND BADGES */
	  .kind-badge { display: inline-block; border: 1px solid var(--border);
	                color: var(--muted); background: var(--soft); border-radius: 4px;
	                padding: .05rem .3rem; font-size: .62rem; font-weight: 800;
	                letter-spacing: .05em; vertical-align: middle; }
	  .kind-users { color: var(--primary); border-color: var(--primary); background: var(--primary-soft); }
	  .kind-computers { color: var(--success); border-color: var(--success); background: var(--success-soft); }
	  .kind-groups { color: var(--warn); border-color: var(--warn); background: var(--warn-soft); }
	  .kind-domains { color: var(--purple); border-color: var(--purple); background: var(--purple-soft); }

  /* PATH CARD */
  .path-card { background: var(--card); border: 1px solid var(--border);
               border-radius: 8px; margin-bottom: 1rem; overflow: hidden; }
  .path-card.best { border-color: var(--success); }
  .path-head { display: flex; align-items: center; gap: .75rem;
               padding: .55rem .85rem; background: var(--soft);
               border-bottom: 1px solid var(--border); flex-wrap: wrap; }
  .path-badge { background: var(--primary); color: var(--bg); font-weight: 700;
                font-size: .7rem; padding: .15rem .5rem; border-radius: 10px;
                letter-spacing: .05em; }
  .path-badge.best { background: var(--success); }
  .path-stat { color: var(--muted); font-size: .78rem; }
  .chain-ascii { padding: .85rem 1rem; margin: 0; color: var(--text);
                 font-family: "SF Mono", Menlo, Consolas, monospace; font-size: .82rem;
                 line-height: 1.6; white-space: pre; overflow-x: auto;
                 border-bottom: 1px solid var(--border); }
  .exploit-only { padding: .8rem 1rem; border-bottom: 1px solid var(--border);
                  background: color-mix(in srgb, var(--success-soft) 55%, transparent); }
  .exploit-hop { display: flex; align-items: center; gap: .45rem; flex-wrap: wrap;
                 padding: .3rem 0; font-size: .82rem; }
  .exploit-num { width: 20px; height: 20px; border-radius: 50%; background: var(--success);
                 color: var(--bg); display: inline-flex; align-items: center;
                 justify-content: center; font-weight: 800; font-size: .68rem; }
  .exploit-desc, .exploit-actor { color: var(--muted); }
  .exploit-actor code { background: var(--purple-soft); color: var(--purple);
                        padding: .1rem .35rem; border-radius: 3px; }
  .graph-chain { border-bottom: 1px solid var(--border); }
  .graph-chain > summary { cursor: pointer; list-style: none; color: var(--muted);
                           font-size: .78rem; font-weight: 700; padding: .55rem 1rem;
                           background: var(--soft); user-select: none; }
  .graph-chain > summary::before { content: "▶ "; font-size: .6rem; }
  .graph-chain[open] > summary::before { content: "▼ "; }
  .graph-chain .chain-ascii { border-bottom: none; }

  /* CHAIN PILLS */
  .path-chain { padding: .75rem 1.25rem; display: flex; flex-wrap: wrap;
                gap: .35rem; align-items: center; }
  .chain-pill { background: var(--soft); border: 1px solid var(--border);
                padding: .25rem .55rem; border-radius: 5px; font-family: monospace;
                font-size: .78rem; color: var(--text); }
  .chain-pill.src { background: var(--success-soft); border-color: var(--success);
                    color: var(--success); font-weight: 600; }
  .chain-pill.dst { background: var(--danger-soft); border-color: var(--danger);
                    color: var(--danger); font-weight: 600; }
  .chain-pill.mini { font-size: .72rem; padding: .15rem .4rem; }
  .chain-rel { color: var(--muted); font-size: .72rem; font-family: monospace;
               padding: 0 .15rem; }
  .chain-rel.mini { font-size: .68rem; }

  /* DCSYNC BANNER */
  .dcsync-banner { background: var(--purple-soft); color: var(--purple);
                   padding: .75rem 1.25rem; border-top: 1px solid var(--border);
                   border-bottom: 1px solid var(--border); font-size: .88rem; }
  .dcsync-banner code { background: var(--card); padding: .1rem .3rem;
                        border-radius: 3px; font-size: .82rem; }

  /* STEPS */
  .path-steps { padding: 0; }
  .step { display: flex; gap: .85rem; padding: .85rem 1rem;
          border-top: 1px solid var(--border); }
  .step:first-child { border-top: none; }
  .step-num { flex-shrink: 0; width: 24px; height: 24px; border-radius: 50%;
              background: var(--primary); color: var(--bg); display: flex;
              align-items: center; justify-content: center; font-weight: 700;
              font-size: .75rem; }
  .step-structural { padding: .35rem 1rem; opacity: .65; }
  .step-structural .step-num { background: var(--soft); color: var(--muted);
                               border: 1px solid var(--border); width: 18px;
                               height: 18px; font-size: .7rem; }
  .step-body { flex: 1; min-width: 0; }
  .step-headline { font-size: .88rem; margin-bottom: .3rem; display: flex;
                   align-items: center; gap: .35rem; flex-wrap: wrap;
                   color: var(--muted); }
  .step-headline code { background: var(--soft); padding: .1rem .35rem;
                        border-radius: 3px; font-size: .8rem; color: var(--text); }
  .step-arrow { color: var(--muted); }
  .step-meta { color: var(--muted); font-size: .78rem; }
  .step-title { font-weight: 700; color: var(--primary); margin-bottom: .15rem;
                font-size: .95rem; }
  .step-explain { color: var(--text); font-size: .85rem; margin-bottom: .45rem;
                  opacity: .9; }
  .step-impact { background: var(--soft); padding: .4rem .7rem;
                 border-radius: 4px; font-size: .82rem; margin-bottom: .55rem;
                 border-left: 3px solid var(--primary); color: var(--text); }
  .step-impact b { color: var(--primary); }

  /* REL TAG */
  .rel-tag { background: var(--warn-soft); color: var(--warn); border: 1px solid var(--warn);
             padding: .1rem .4rem; border-radius: 4px; font-family: monospace;
             font-size: .72rem; font-weight: 600; }
  .rel-tag-alt { background: transparent; color: var(--muted); border-color: var(--border);
                 font-weight: 500; }

  /* IDENTITY CHANGE */
  .ident-change { color: var(--purple); font-size: .85rem; margin-top: .5rem; }
  .ident-change code { background: var(--purple-soft); padding: .1rem .35rem;
                       border-radius: 3px; color: var(--purple); }
  .ident-arrow { font-weight: 700; }

	  /* COMMANDS */
  .cmd-details { margin: .35rem 0 0; }
  .cmd-details > summary { cursor: pointer; color: var(--primary);
                           font-size: .76rem; font-weight: 600; padding: .15rem 0;
                           list-style: none; user-select: none; }
  .cmd-details > summary::before { content: "▶ "; font-size: .6rem; }
  .cmd-details[open] > summary::before { content: "▼ "; }
	  .cmd-details > summary:hover { color: var(--text); }
	  .cmd-box { margin-top: .35rem; border: 1px solid var(--border);
	             border-radius: 6px; overflow: hidden; background: var(--code-bg); }
	  .cmd-toolbar { display: flex; align-items: center; justify-content: space-between;
	                 gap: .75rem; padding: .35rem .55rem; background: var(--soft);
	                 border-bottom: 1px solid var(--border); color: var(--muted);
	                 font-size: .72rem; font-weight: 700; }
	  .copy-btn { border: 1px solid var(--border); background: var(--card);
	              color: var(--text); border-radius: 4px; padding: .15rem .45rem;
	              font: inherit; cursor: pointer; }
	  .copy-btn:hover { border-color: var(--primary); color: var(--primary); }
	  .cmd-pre { background: var(--code-bg); color: var(--code-text);
	             padding: .85rem 1rem; margin: 0; font-size: .8rem;
             line-height: 1.7; overflow-x: auto;
             white-space: pre-wrap; word-break: break-word; }
  .cmd-pre.small { font-size: .76rem; padding: .55rem .75rem;
                   border-radius: 5px; margin-top: .35rem; }
  .cmd-pre .cmt { color: var(--code-cmt); }
  .placeholder { color: var(--warn); background: var(--warn-soft);
                 border: 1px solid color-mix(in srgb, var(--warn) 55%, transparent);
                 border-radius: 3px; padding: 0 .18rem; font-weight: 700; }

  /* FLAG PILLS */
  .flag-pill { display: inline-block; font-size: .68rem; font-weight: 600;
               padding: .1rem .45rem; border-radius: 10px; border: 1px solid;
               margin-left: .25rem; }

  /* PIVOTS / INTERMEDIATES */
  .pivot-card { background: var(--card); border: 1px solid var(--border);
                border-radius: 6px; margin-bottom: .85rem; overflow: hidden; }
  details.pivot-card > summary { cursor: pointer; list-style: none; user-select: none; }
  details.pivot-card > summary::-webkit-details-marker { display: none; }
  details.pivot-card > summary.pivot-head { border-bottom: 1px solid transparent; }
  details.pivot-card[open] > summary.pivot-head { border-bottom-color: var(--border); }
  details.pivot-card > summary.pivot-head::before {
    content: "▶"; color: var(--muted); font-size: .65rem; margin-right: .15rem;
  }
  details.pivot-card[open] > summary.pivot-head::before { content: "▼"; }
  .pivot-head { display: flex; align-items: center; gap: .55rem;
                padding: .55rem .85rem; background: var(--soft);
                border-bottom: 1px solid var(--border); flex-wrap: wrap; }
  .pivot-rank { background: var(--primary); color: var(--bg); font-weight: 700;
                font-size: .7rem; padding: .15rem .45rem; border-radius: 8px; }
  .pivot-name { font-weight: 600; color: var(--text); }
  .pivot-name code { background: var(--soft); padding: .1rem .35rem;
                     border-radius: 3px; }
  .pivot-stat { color: var(--muted); font-size: .78rem; }
  .pivot-body { padding: .65rem .85rem; }
  .pivot-chain-label { color: var(--muted); font-size: .78rem;
                       margin: .55rem 0 .25rem; font-weight: 600; }

  /* VECTOR (out-of-band attack) */
  .vector-block { background: var(--soft); border-left: 3px solid var(--warn);
                  padding: .55rem .75rem; border-radius: 4px;
                  margin-bottom: .5rem; }
  .vector-name { font-weight: 600; font-size: .85rem; color: var(--warn); }
  .vector-explain { color: var(--text); font-size: .82rem; margin-top: .2rem;
                    opacity: .9; }

  /* QUICK-WINS */
  .quickwin-summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
                      gap: .5rem; margin-bottom: .85rem; }
  .quickwin-summary .qw-tile { display: flex; align-items: center; gap: .55rem;
                               border-radius: 6px; padding: .45rem .6rem; }
  .quickwin-summary .qw-tile-num { font-size: 1rem; line-height: 1; }
  .quickwin-summary .qw-tile-cat { margin-top: 0; }
  .qw-cat { margin-bottom: 1.25rem; padding-bottom: 1rem;
            border-bottom: 1px dashed var(--border); }
  details.qw-cat > summary { cursor: pointer; list-style: none; user-select: none; }
  details.qw-cat > summary::before { content: "▶"; color: var(--muted); font-size: .65rem; }
  details.qw-cat[open] > summary::before { content: "▼"; }
  .qw-cat:last-child { border-bottom: none; }
  .qw-cat-head { display: flex; align-items: baseline; gap: .55rem;
                 margin-bottom: .35rem; }
  .qw-cat-title { color: var(--warn); font-weight: 700; font-size: .98rem; }
  .qw-cat-explain { color: var(--muted); font-size: .82rem;
                    margin-bottom: .65rem; }
  .qw-count-small { background: var(--soft); color: var(--muted);
                    padding: .1rem .4rem; border-radius: 8px;
                    font-size: .7rem; font-weight: 700; }
  .qw-items { display: flex; flex-direction: column; gap: .55rem; }
  .qw-item { background: var(--soft); border: 1px solid var(--border);
             border-radius: 5px; padding: .55rem .75rem; }
  .qw-item-name { font-size: .88rem; margin-bottom: .2rem; }
  .qw-item-name code { background: var(--card); padding: .1rem .35rem;
                       border-radius: 3px; color: var(--text); }
  .qw-item-detail { color: var(--muted); font-size: .8rem;
                    margin-bottom: .35rem; }
  .qw-item .cmd-pre { margin-top: .35rem; font-size: .76rem;
                      padding: .55rem .7rem; border-radius: 4px; }
  .qw-more { margin-top: .6rem; }
  .qw-more > summary { cursor: pointer; color: var(--primary); font-size: .78rem;
                       font-weight: 700; list-style: none; }

  /* FINDINGS */
  .findings-list { display: flex; flex-direction: column; gap: .65rem; }
  .finding-row { display: grid; grid-template-columns: 42px minmax(0, 1fr);
                 gap: .7rem; background: var(--card); border: 1px solid var(--border);
                 border-radius: 6px; padding: .7rem .8rem; }
  .finding-score { display: grid; place-items: center; align-self: start;
                   width: 34px; height: 34px; border-radius: 50%;
                   background: var(--soft); color: var(--text); font-weight: 800;
                   border: 1px solid var(--border); }
  .finding-score.sev-10, .finding-score.sev-9 { color: var(--danger); border-color: var(--danger); }
  .finding-score.sev-8, .finding-score.sev-7 { color: var(--warn); border-color: var(--warn); }
  .finding-title { font-weight: 700; color: var(--text); font-size: .9rem; }
  .finding-meta { display: flex; flex-wrap: wrap; gap: .45rem; color: var(--muted);
                  font-size: .76rem; margin-top: .25rem; }
  .finding-meta code { background: var(--soft); padding: .1rem .35rem;
                       border-radius: 3px; color: var(--text); }
  .finding-evidence { color: var(--muted); font-size: .82rem; margin-top: .35rem; }

  /* DATA TABLE */
  .data-table { width: 100%; border-collapse: collapse; margin-top: .5rem; }
  .data-table th, .data-table td { padding: .45rem .75rem; text-align: left;
                                   border-bottom: 1px solid var(--border);
                                   font-size: .85rem; }
  .data-table th { background: var(--soft); font-weight: 600; color: var(--muted);
                   font-size: .75rem; letter-spacing: .03em; text-transform: uppercase; }
  .data-table .num { font-family: monospace; color: var(--muted); }
  .data-table code { background: var(--soft); padding: .1rem .35rem;
                     border-radius: 3px; }
  .chain-cell { white-space: nowrap; overflow-x: auto; max-width: 480px; }
  .object-control-block { display: flex; flex-direction: column; gap: .55rem; }
  .object-tools { display: flex; justify-content: flex-end; }
  .object-filter { width: min(260px, 100%); background: var(--soft); color: var(--text);
                   border: 1px solid var(--border); border-radius: 5px;
                   padding: .35rem .55rem; font: inherit; font-size: .8rem; }
  .object-filter:focus { outline: none; border-color: var(--primary); }
  .relation-chips { display: flex; flex-wrap: wrap; gap: .35rem; }
  .relation-chip { display: inline-flex; align-items: center; gap: .35rem;
                   border: 1px solid var(--border); background: var(--soft);
                   border-radius: 999px; padding: .15rem .45rem; color: var(--muted);
                   font-size: .72rem; }
  .relation-chip b { color: var(--text); }
  .object-table { margin-top: 0; }
  .show-all { border: 1px dashed var(--border); border-radius: 6px;
              padding: .5rem .65rem; }
  .show-all > summary { cursor: pointer; color: var(--primary); font-size: .8rem;
                        font-weight: 700; list-style: none; }

  /* STATS */
  .stats-details { margin-bottom: 1.25rem; background: var(--card);
                   border: 1px solid var(--border); border-radius: 8px;
                   padding: .65rem 1rem; }
  .stats-details > summary { cursor: pointer; color: var(--muted);
                             font-size: .82rem; font-weight: 600; }

  /* USER BLOCK (multi-user) */
  .user-block { margin-bottom: 1.5rem; padding-bottom: 1rem;
                border-bottom: 1px dashed var(--border); }
  .user-block:last-of-type { border-bottom: none; }
  .user-tag { color: var(--success); font-size: .9rem; margin-bottom: .5rem; }
  .user-tag code { background: var(--soft); padding: .15rem .4rem;
                   border-radius: 4px; color: var(--success); }

  /* USER SECTION (multi-user) */
  .user-section { margin-bottom: 2rem; }
  .user-section-head { background: var(--card); border: 1px solid var(--border);
                       border-left: 4px solid var(--primary); border-radius: 8px;
                       padding: .65rem 1rem; margin-bottom: 1rem; }
  .user-section-head .label { font-size: .68rem; color: var(--muted);
                              letter-spacing: .12em; text-transform: uppercase;
                              font-weight: 700; margin-bottom: .15rem; }
  .user-section-head .who { font-family: monospace; font-weight: 600; }
  .user-section .verdict { margin-bottom: .85rem; }
  .empty-block { background: var(--soft); border: 1px solid var(--border);
                 border-radius: 8px; padding: 1rem; color: var(--muted);
                 text-align: center; font-size: .9rem; }

  .section-banner { border-left: 4px solid var(--primary); background: var(--soft);
                    padding: .75rem 1.25rem; border-radius: 8px; margin-bottom: 1.5rem;
                    display: flex; align-items: center; gap: .75rem; }
  .section-banner .banner-title { font-size: .8rem; letter-spacing: .1em;
                                  text-transform: uppercase; font-weight: 800; }
  .section-banner .banner-meta { font-size: .75rem; color: var(--muted); }
  .section-banner.attack { border-left-color: var(--success); background: var(--success-soft); }
  .section-banner.attack .banner-title { color: var(--success); }
  .section-banner.node { border-left-color: var(--purple); background: var(--purple-soft); }
  .section-banner.node .banner-title { color: var(--purple); }

  @media (max-width: 720px) {
    body { padding: .75rem; font-size: 13px; }
    .title { line-height: 1.8; }
    .sticky-nav { top: 0; margin-left: -.75rem; margin-right: -.75rem;
                  padding-left: .75rem; padding-right: .75rem; }
    .report-section { padding: .8rem; border-radius: 8px; }
    .plan-head, .path-head, .pivot-head { align-items: flex-start; }
    .plan-head { flex-direction: column; }
    .plan-stats { justify-content: flex-start; }
    .step { gap: .55rem; padding: .65rem .75rem; }
    .step-num, .plan-num { width: 22px; height: 22px; }
    .exploit-hop { align-items: flex-start; }
    .data-table { display: block; overflow-x: auto; white-space: nowrap; }
    .quickwin-summary { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .object-tools { justify-content: stretch; }
    .object-filter { width: 100%; }
  }

  footer { color: var(--muted); font-size: .75rem; padding-top: 1rem;
           border-top: 1px solid var(--border); margin-top: 2rem; text-align: center; }
  footer a { color: var(--primary); text-decoration: none; }
</style>
</head>
<body>
"""
