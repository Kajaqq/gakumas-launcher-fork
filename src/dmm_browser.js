// Injected into the DMM browser window on every page load.
// Adds an address bar with Back/Forward. Uses plain browser navigation so it
// works on external pages (where Tauri IPC is not available).
(function () {
  if (window.top !== window || window.__gakumasDmmBarInstalled) return;
  window.__gakumasDmmBarInstalled = true;

  function install() {
    if (!document.body || document.getElementById('__gakumas_dmm_bar')) return;

    const bar = document.createElement('div');
    bar.id = '__gakumas_dmm_bar';
    bar.style.cssText = [
      'position:fixed', 'top:0', 'left:0', 'right:0', 'height:44px',
      'display:flex', 'align-items:center', 'gap:8px', 'padding:6px 10px',
      'box-sizing:border-box', 'background:#f5f5f4', 'border-bottom:2px solid #e6e4e2',
      'z-index:2147483647', 'font-family:sans-serif', 'font-size:14px'
    ].join(';');

    const buttonStyle = [
      'height:30px', 'min-width:34px', 'padding:0 10px', 'border:0', 'border-radius:6px',
      'background:#e6e4e2', 'color:#4f4b4b', 'cursor:pointer', 'font-weight:bold', 'font-size:16px'
    ].join(';');

    const back = document.createElement('button');
    back.textContent = '←';
    back.title = 'Back';
    back.style.cssText = buttonStyle;

    const forward = document.createElement('button');
    forward.textContent = '→';
    forward.title = 'Forward';
    forward.style.cssText = buttonStyle;

    const input = document.createElement('input');
    input.type = 'text';
    input.value = window.location.href;
    input.style.cssText = [
      'flex:1', 'height:30px', 'box-sizing:border-box', 'padding:0 10px',
      'border:1px solid #ccc', 'border-radius:6px', 'font-size:14px'
    ].join(';');

    const goBtn = document.createElement('button');
    goBtn.textContent = 'Go';
    goBtn.style.cssText = [
      'height:30px', 'padding:0 14px', 'border:0', 'border-radius:6px',
      'background:#ff7b00', 'color:#fff', 'cursor:pointer', 'font-weight:bold'
    ].join(';');

    function go(url) {
      if (!url) return;
      if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(url)) url = 'https://' + url;
      try {
        const target = new URL(url);
        if (!['https:', 'http:'].includes(target.protocol)) throw new Error();
        window.location.assign(target.href);
      } catch (_) {
        input.setCustomValidity('Enter a valid HTTP or HTTPS address');
        input.reportValidity();
      }
    }

    function navigate() {
      input.value = input.value.trim();
      go(input.value);
    }

    back.addEventListener('click', function () { window.history.back(); });
    forward.addEventListener('click', function () { window.history.forward(); });
    goBtn.addEventListener('click', navigate);
    input.addEventListener('input', () => input.setCustomValidity(''));
    input.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') { e.preventDefault(); navigate(); }
    });

    bar.appendChild(back);
    bar.appendChild(forward);
    bar.appendChild(input);
    bar.appendChild(goBtn);
    (document.body || document.documentElement).appendChild(bar);
    document.body.style.paddingTop = '44px';
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', install);
  } else {
    install();
  }
})();
