(() => {
  "use strict";

  // Curseur partage entre l'atelier et la page Compte : les deux pages chargent
  // ce fichier, donc l'effet ne depend pas de la page courante.
  const TARGETS =
    "a[href], button:not(:disabled), [role='button'], summary, label, select, .color-picker";

  function initCursor() {
    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const isTouch = window.matchMedia("(pointer: coarse)").matches;
    // Sans pointeur fin, le curseur systeme reste : pas de doublon a l'ecran.
    if (reduceMotion || isTouch) return;

    const dot = document.createElement("div");
    dot.className = "cursor-dot";
    dot.setAttribute("aria-hidden", "true");

    const ring = document.createElement("div");
    ring.className = "cursor-ring";
    ring.setAttribute("aria-hidden", "true");

    // Le libelle vit dans un element separe, positionne sur le pointeur et
    // jamais au centre de la cible : une pastille opaque cache le bouton qu'elle
    // designe, ce qui lisait comme un bug de zoom.
    const chip = document.createElement("div");
    chip.className = "cursor-chip";
    chip.setAttribute("aria-hidden", "true");
    const chipText = document.createElement("span");
    chipText.className = "cursor-chip-text";
    chip.appendChild(chipText);

    document.body.append(dot, ring, chip);
    document.body.classList.add("has-custom-cursor");

    let mouseX = 0;
    let mouseY = 0;
    let ringX = 0;
    let ringY = 0;
    let targetX = 0;
    let targetY = 0;
    let scale = 1;
    let targetScale = 1;
    let magnet = null;
    let rafId = null;

    function setMagnet(el) {
      if (magnet === el) return;
      magnet = el || null;
      const text = magnet ? (magnet.dataset.cursor || "").trim() : "";
      chipText.textContent = text;
      chip.classList.toggle("is-visible", Boolean(text));
      ring.classList.toggle("is-magnet", Boolean(magnet));
      targetScale = magnet ? 1.7 : 1;
    }

    function show() {
      dot.style.opacity = "1";
      ring.style.opacity = "1";
    }

    function onMove(event) {
      mouseX = event.clientX;
      mouseY = event.clientY;
      if (!ringX && !ringY) {
        ringX = mouseX;
        ringY = mouseY;
      }
      targetX = mouseX;
      targetY = mouseY;
      show();
      setMagnet(event.target instanceof Element ? event.target.closest(TARGETS) : null);
      if (!rafId) rafId = requestAnimationFrame(update);
    }

    function onLeave() {
      dot.style.opacity = "0";
      ring.style.opacity = "0";
      chip.classList.remove("is-visible");
    }

    function update() {
      // Le rect est lu avant toute ecriture de style : pas de layout synchrone.
      if (magnet) {
        if (!magnet.isConnected) {
          setMagnet(null);
        } else {
          const rect = magnet.getBoundingClientRect();
          if (rect.width || rect.height) {
            // Effet magnetique : l'anneau est aspire vers le centre de la cible.
            targetX = rect.left + rect.width / 2;
            targetY = rect.top + rect.height / 2;
          } else {
            setMagnet(null);
          }
        }
      }

      ringX += (targetX - ringX) * 0.18;
      ringY += (targetY - ringY) * 0.18;
      scale += (targetScale - scale) * 0.18;

      dot.style.transform = `translate3d(${mouseX}px, ${mouseY}px, 0)`;
      ring.style.transform = `translate3d(${ringX}px, ${ringY}px, 0) scale(${scale})`;
      chip.style.transform = `translate3d(${mouseX + 16}px, ${mouseY + 16}px, 0)`;

      const settled =
        Math.abs(targetX - ringX) < 0.15 &&
        Math.abs(targetY - ringY) < 0.15 &&
        Math.abs(targetScale - scale) < 0.002;
      rafId = settled ? null : requestAnimationFrame(update);
    }

    document.addEventListener("mousemove", onMove, { passive: true });
    document.addEventListener("mousedown", () => document.body.classList.add("is-selecting"));
    document.addEventListener("mouseup", () => document.body.classList.remove("is-selecting"));
    document.documentElement.addEventListener("mouseleave", onLeave);
    window.addEventListener("blur", onLeave);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initCursor);
  } else {
    initCursor();
  }
})();
