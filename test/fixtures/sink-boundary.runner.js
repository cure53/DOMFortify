/**
 * Sink-boundary matrix runner (shared by the protected fixture and the unprotected canary).
 *
 * It runs every vector in GENUINE page context - this file executes as the page loads, NOT through
 * Playwright's page.evaluate. That is deliberate and load-bearing: page.evaluate runs in a CDP context
 * that bypasses Trusted Types enforcement for eval()/Function() specifically (innerHTML and setTimeout
 * stay gated), so measuring those from page.evaluate falsely reports them as executed. Driving the
 * sinks from the page itself is the only honest way to test eval/Function. Do not "simplify" this into
 * page.evaluate.
 *
 * Each payload calls window.__H('<label>'); the spec reads window.__fired after a short settle so async
 * sinks (string setTimeout, script.src) are captured too. window.__matrix records whether each sink
 * threw (refused). The spec cross-references the two.
 */
(function () {
  var host = document.getElementById('sb') || document.body;
  var matrix = [];
  window.__fired = {};
  window.__H = function (label) {
    window.__fired[label] = true;
  };
  // NOTE: labels are interpolated into injected handler strings, so they MUST stay quote-free.
  function q(L) {
    return "window.__H('" + L + "')";
  }
  function fresh() {
    var c = document.createElement('div');
    host.appendChild(c);
    return c;
  }
  function vec(label, category, run) {
    var threw = false,
      msg = '';
    try {
      run(label);
    } catch (e) {
      threw = true;
      msg = String((e && e.message) || e).slice(0, 90);
    }
    matrix.push({ label: label, category: category, threw: threw, msg: msg });
  }

  // HTML sinks: inject an inline handler as markup, then click it. Stripped by the sanitizer -> no run.
  vec('innerHTML', 'html', function (L) {
    var c = fresh();
    c.innerHTML = '<div onclick="' + q(L) + '">x</div>';
    var d = c.querySelector('div');
    if (d) d.click();
  });
  vec('outerHTML', 'html', function (L) {
    var t = fresh();
    var s = document.createElement('span');
    t.appendChild(s);
    s.outerHTML = '<b onclick="' + q(L) + '">x</b>';
    var b = t.querySelector('b');
    if (b) b.click();
  });
  vec('insertAdjacentHTML', 'html', function (L) {
    var c = fresh();
    c.insertAdjacentHTML('beforeend', '<i onclick="' + q(L) + '">x</i>');
    var i = c.querySelector('i');
    if (i) i.click();
  });
  vec('createContextualFragment', 'html', function (L) {
    var c = fresh();
    var r = document.createRange();
    r.selectNode(c);
    c.appendChild(r.createContextualFragment('<u onclick="' + q(L) + '">x</u>'));
    var u = c.querySelector('u');
    if (u) u.click();
  });
  vec('template.innerHTML', 'html', function (L) {
    var c = fresh();
    var t = document.createElement('template');
    t.innerHTML = '<s onclick="' + q(L) + '">x</s>';
    c.appendChild(t.content.cloneNode(true));
    var s = c.querySelector('s');
    if (s) s.click();
  });

  // String-to-code script sinks: refused by createScript / createScriptURL (return null -> sink throws).
  vec('eval', 'script', function (L) {
    eval(q(L));
  });
  vec('Function', 'script', function (L) {
    Function(q(L))();
  });
  vec('setTimeout(string)', 'script', function (L) {
    setTimeout(q(L), 0);
  });
  vec('script.text', 'script', function (L) {
    var s = document.createElement('script');
    s.text = q(L);
    fresh().appendChild(s);
  });
  vec('script.src', 'script', function (L) {
    var s = document.createElement('script');
    s.src = 'data:text/javascript,' + encodeURIComponent(q(L));
    fresh().appendChild(s);
  });

  // Event-handler attribute set via setAttribute: also a TrustedScript sink, also refused.
  vec('setAttribute-onclick', 'attr', function (L) {
    var b = document.createElement('button');
    fresh().appendChild(b);
    b.setAttribute('onclick', q(L));
    b.click();
  });

  // Boundary marker: assigning a FUNCTION to a handler property is not a string sink and not reachable
  // by markup injection; Trusted Types does not see it. Documented as outside the contract, not a bug.
  vec('el.onclick = fn', 'boundary', function (L) {
    var b = document.createElement('button');
    fresh().appendChild(b);
    b.onclick = function () {
      window.__H(L);
    };
    b.click();
  });

  window.__matrix = matrix;
  window.__matrixReady = true;
})();
