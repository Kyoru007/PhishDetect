const $ = id => document.getElementById(id);
const savedTheme = localStorage.getItem('theme');
document.body.classList.toggle('light', savedTheme === 'light' || (!savedTheme && matchMedia('(prefers-color-scheme: light)').matches));
$('theme').onclick = () => { document.body.classList.toggle('light'); localStorage.setItem('theme', document.body.classList.contains('light') ? 'light' : 'dark'); };
document.querySelectorAll('[data-url]').forEach(button => button.onclick = () => { $('url').value = button.dataset.url; $('form').requestSubmit(); });
$('form').onsubmit = async event => {
  event.preventDefault(); $('error').hidden = true; $('submit').disabled = true; $('submit').textContent = 'Analyzing…';
  try {
    const response = await fetch('/predict', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({url:$('url').value.trim()})});
    const data = await response.json();
    if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'Please enter a valid URL (maximum 8,192 characters).');
    $('empty').hidden = true; $('result').hidden = false;
    $('score').textContent = `${(data.probability * 100).toFixed(1)}%`;
    $('gauge').style.setProperty('--score', `${data.probability * 360}deg`);
    $('gauge').style.setProperty('--tone', data.probability >= data.threshold ? 'var(--red)' : 'var(--accent)');
    $('verdict').textContent = data.verdict;
    $('threshold').textContent = `Decision threshold: ${(data.threshold * 100).toFixed(1)}% · Not a safety verdict`;
    $('dataset').textContent = `${data.model} · ${data.dataset_mode === 'synthetic' ? 'SYNTHETIC TRAINING DATA — demo only' : data.dataset_mode}`;
    $('notice').textContent = data.notice; $('method').textContent = data.explanation_method;
    $('flags').replaceChildren(...(data.red_flags.length ? data.red_flags : ['No listed heuristic flags. Risk can still be present.']).map(flag => { const li = document.createElement('li'); li.textContent = flag; return li; }));
    const max = Math.max(.001, ...data.contributions.map(c => Math.abs(c.contribution)));
    $('bars').replaceChildren(...data.contributions.map(c => {
      const row = document.createElement('div'); row.className = 'bar-row';
      const label = document.createElement('span'); label.className = 'bar-label'; label.textContent = c.feature.replaceAll('_', ' ');
      const track = document.createElement('div'); track.className = 'bar-track';
      const fill = document.createElement('div'); fill.className = 'bar-fill' + (c.contribution < 0 ? ' negative' : ''); fill.style.width = `${Math.abs(c.contribution) / max * 100}%`; track.append(fill);
      const number = document.createElement('span'); number.className = 'bar-number'; number.textContent = `${c.contribution >= 0 ? '+' : ''}${(c.contribution * 100).toFixed(1)} pp`;
      row.append(label, track, number); return row;
    }));
  } catch(error) { $('error').textContent = error.message; $('error').hidden = false; }
  finally { $('submit').disabled = false; $('submit').textContent = 'Analyze URL ↗'; }
};
