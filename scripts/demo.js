/* Read-only filtering of Python-rendered sample rows. No service calls or storage. */
const form = document.querySelector('.filters');
const body = document.querySelector('.findings-table tbody');
const original = [...body.rows];
const params = new URLSearchParams(location.search);
for (const field of form.elements) {
  if (field.name && params.has(field.name)) field.value = params.get(field.name);
}
const q = form.elements.q.value.trim().toLowerCase();
const owner = form.elements.owner.value;
const focus = form.elements.focus.value || 'all';
const state = form.elements.state.value || 'actionable';
const sort = form.elements.sort.value;
const number = (row, pattern) => Number(row.cells[0].innerText.match(pattern)?.[1] || 0);
const visible = original.filter(row => {
  const text = row.innerText.toLowerCase();
  const team = row.cells[3].childNodes[0].textContent.trim();
  return text.includes(q) && (!owner || owner === team)
    && ['actionable', 'all', 'open'].includes(state)
    && (focus === 'all' || (focus === 'overdue' && row.querySelector('.late'))
      || (focus === 'exploited' && row.querySelector('.exploited'))
      || (focus === 'exposed' && row.querySelector('.exposed')));
});
if (sort === 'severity') visible.sort((a, b) => number(b, /Sev ([\d.]+)/) - number(a, /Sev ([\d.]+)/));
if (sort === 'deadline') visible.sort((a, b) => a.cells[4].querySelector('small').textContent.localeCompare(b.cells[4].querySelector('small').textContent));
body.replaceChildren(...visible);
document.querySelector('.sectionhead strong').textContent = visible.length;
if (!visible.length) {
  const cell = body.insertRow().insertCell();
  cell.colSpan = 5;
  cell.textContent = 'No sample findings match this view. Reset filters to explore the queue.';
}
form.method = 'get';
form.action = 'index.html';
