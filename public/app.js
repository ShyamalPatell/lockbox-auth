// Small helpers for the forms. These are only for convenience: the server
// re-checks every rule, so turning JavaScript off can't skip any security.
(function () {
  'use strict';

  // Show / hide password buttons
  document.querySelectorAll('[data-toggle]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var input = document.getElementById(btn.getAttribute('data-toggle'));
      if (!input) return;
      var show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      btn.textContent = show ? 'Hide' : 'Show';
      btn.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
    });
  });

  // Live password checklist
  document.querySelectorAll('[data-rules-for]').forEach(function (list) {
    var input = document.getElementById(list.getAttribute('data-rules-for'));
    if (!input) return;
    var rules = {
      len: function (v) { return v.length >= 10; },
      special: function (v) { return /[^A-Za-z0-9\s]/.test(v); }
    };
    function update() {
      list.querySelectorAll('[data-rule]').forEach(function (li) {
        var ok = rules[li.getAttribute('data-rule')](input.value);
        li.classList.toggle('ok', ok);
      });
    }
    input.addEventListener('input', update);
    update();
  });

  // "Passwords match" note on confirm fields
  document.querySelectorAll('[data-match]').forEach(function (confirm) {
    var original = document.getElementById(confirm.getAttribute('data-match'));
    if (!original) return;
    var note = document.createElement('p');
    note.className = 'match-note';
    note.setAttribute('aria-live', 'polite');
    confirm.closest('.field').appendChild(note);
    function update() {
      if (!confirm.value) { note.textContent = ''; note.className = 'match-note'; return; }
      var same = confirm.value === original.value;
      note.textContent = same ? 'Passwords match' : 'Passwords don’t match yet';
      note.className = 'match-note ' + (same ? 'ok' : 'bad');
    }
    confirm.addEventListener('input', update);
    original.addEventListener('input', update);
  });

  // Prevent double-submits
  document.querySelectorAll('form').forEach(function (form) {
    form.addEventListener('submit', function () {
      var b = form.querySelector('button[type=submit]');
      if (b) setTimeout(function () { b.disabled = true; }, 0);
    });
  });
})();
