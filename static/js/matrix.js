// PhantomVault — Matrix rain background
(function () {
  const canvas = document.getElementById("matrix-bg");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");

  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
  }
  resize();
  window.addEventListener("resize", resize);

  const chars = "01アイウエオカキクケコサシスセソタチツテトVAULT01";
  const fontSize = 14;
  let columns, drops;

  function setup() {
    columns = Math.floor(canvas.width / fontSize);
    drops = new Array(columns).fill(0).map(() => Math.random() * -50);
  }
  setup();
  window.addEventListener("resize", setup);

  const colors = ["#00F5FF", "#9B5DE5", "#00FF88"];

  function draw() {
    ctx.fillStyle = "rgba(6,6,8,0.06)";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.font = `${fontSize}px JetBrains Mono, monospace`;

    for (let i = 0; i < columns; i++) {
      const text = chars[Math.floor(Math.random() * chars.length)];
      ctx.fillStyle = colors[Math.floor(Math.random() * colors.length)];
      ctx.fillText(text, i * fontSize, drops[i] * fontSize);
      if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
        drops[i] = 0;
      }
      drops[i]++;
    }
  }
  setInterval(draw, 45);
})();
