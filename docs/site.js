const steps = [...document.querySelectorAll('.demo-step')];
const output = document.getElementById('demo-output');
const state = document.getElementById('demo-state');

for (const [index, step] of steps.entries()) {
  step.addEventListener('click', () => {
    for (const item of steps) item.setAttribute('aria-pressed', 'false');
    step.setAttribute('aria-pressed', 'true');
    state.textContent = step.dataset.state;
    output.textContent = JSON.stringify(JSON.parse(step.dataset.output), null, 2);
  });

  step.addEventListener('keydown', (event) => {
    if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return;
    event.preventDefault();
    const direction = event.key === 'ArrowDown' ? 1 : -1;
    const next = (index + direction + steps.length) % steps.length;
    steps[next].focus();
    steps[next].click();
  });
}

if (steps.length) steps[0].click();
