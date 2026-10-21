(function () {
  'use strict';

  // ---- Menu mobile --------------------------------------------------------
  var toggle = document.querySelector('.nav-toggle');
  if (toggle) {
    toggle.addEventListener('click', function () {
      var open = document.body.classList.toggle('nav-open');
      toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
    document.querySelectorAll('.nav-links a').forEach(function (a) {
      a.addEventListener('click', function () { document.body.classList.remove('nav-open'); });
    });
  }

  // ---- Avisos (toasts) somem sozinhos -------------------------------------
  document.querySelectorAll('.toast').forEach(function (t) {
    setTimeout(function () {
      t.style.transition = 'opacity .4s';
      t.style.opacity = '0';
      setTimeout(function () { t.remove(); }, 450);
    }, 6500);
  });

  // ---- Mostrar/ocultar senha ----------------------------------------------
  document.querySelectorAll('[data-toggle-password]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var input = document.getElementById(btn.getAttribute('data-toggle-password'));
      if (!input) return;
      var show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      btn.textContent = show ? 'Ocultar' : 'Mostrar';
    });
  });

  // ---- Copiar texto --------------------------------------------------------
  document.querySelectorAll('[data-copy]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var target = document.getElementById(btn.getAttribute('data-copy'));
      if (!target) return;
      var text = target.textContent.trim();
      var done = function () {
        var old = btn.textContent;
        btn.textContent = 'Copiado!';
        setTimeout(function () { btn.textContent = old; }, 1800);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done);
      } else {
        var range = document.createRange();
        range.selectNodeContents(target);
        var sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        try { document.execCommand('copy'); done(); } catch (e) { /* ignora */ }
        sel.removeAllRanges();
      }
    });
  });

  // ---- Confirmação antes de ações sensíveis --------------------------------
  document.querySelectorAll('form[data-confirm]').forEach(function (form) {
    form.addEventListener('submit', function (ev) {
      if (!window.confirm(form.getAttribute('data-confirm'))) ev.preventDefault();
    });
  });

  // ---- Máscaras do cartão (checkout) ---------------------------------------
  var num = document.querySelector('input[name="numero"]');
  var exp = document.querySelector('input[name="validade"]');
  var cvv = document.querySelector('input[name="cvv"]');
  var brand = document.getElementById('card-brand');

  function brandOf(d) {
    if (/^4/.test(d)) return 'Visa';
    if (/^(5[1-5]|2[2-7])/.test(d)) return 'Mastercard';
    if (/^3[47]/.test(d)) return 'Amex';
    return '';
  }
  if (num) {
    num.addEventListener('input', function () {
      var d = num.value.replace(/\D/g, '').slice(0, 19);
      num.value = d.replace(/(.{4})/g, '$1 ').trim();
      if (brand) brand.textContent = brandOf(d);
    });
  }
  if (exp) {
    exp.addEventListener('input', function () {
      var d = exp.value.replace(/\D/g, '').slice(0, 4);
      exp.value = d.length > 2 ? d.slice(0, 2) + '/' + d.slice(2) : d;
    });
  }
  if (cvv) {
    cvv.addEventListener('input', function () { cvv.value = cvv.value.replace(/\D/g, '').slice(0, 4); });
  }

  // ---- Simulação da verificação (página inicial) ---------------------------
  var demo = document.getElementById('demo');
  if (demo) {
    var btn = demo.querySelector('[data-demo-start]');
    var bar = demo.querySelector('.progress > div');
    var dot = demo.querySelector('.dot');
    var title = demo.querySelector('[data-demo-title]');
    var sub = demo.querySelector('[data-demo-sub]');
    var rows = Array.prototype.slice.call(demo.querySelectorAll('.demo-row'));
    var running = false;

    var reset = function () {
      rows.forEach(function (r) {
        r.className = 'demo-row';
        r.querySelector('.state').textContent = 'aguardando';
      });
      bar.style.width = '0';
    };

    var finish = function (hadThreat) {
      running = false;
      btn.disabled = false;
      btn.textContent = 'Repetir simulação';
      dot.className = hadThreat ? 'dot alert' : 'dot';
      title.textContent = hadThreat ? '1 ameaça isolada' : 'Sistema protegido';
      sub.textContent = hadThreat ? 'O arquivo foi movido para a quarentena' : 'Nenhuma ameaça encontrada';
    };

    btn.addEventListener('click', function () {
      if (running) return;
      running = true;
      reset();
      btn.disabled = true;
      btn.textContent = 'Verificando…';
      dot.className = 'dot busy';
      title.textContent = 'Verificação em andamento';
      sub.textContent = 'Analisando arquivos…';

      var i = 0, hadThreat = false;
      var step = function () {
        if (i >= rows.length) { finish(hadThreat); return; }
        var row = rows[i];
        row.querySelector('.state').textContent = 'verificando…';
        setTimeout(function () {
          var threat = row.getAttribute('data-threat');
          if (threat) {
            hadThreat = true;
            row.className = 'demo-row threat';
            row.querySelector('.state').textContent = threat;
          } else {
            row.className = 'demo-row clean';
            row.querySelector('.state').textContent = row.getAttribute('data-clean');
          }
          i += 1;
          bar.style.width = Math.round((i / rows.length) * 100) + '%';
          step();
        }, 700);
      };
      step();
    });
  }
})();
