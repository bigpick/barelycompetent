function getGiscusTheme() {
  const theme = localStorage.getItem("theme");
  const giscusTheme = theme === "dark" ? "dark" : "light";
  return giscusTheme;
}

function setGiscusTheme() {
  function sendMessage(message) {
    const iframe = document.querySelector('iframe.giscus-frame');
    if (!iframe) return;
    iframe.contentWindow.postMessage({ giscus: message }, 'https://giscus.app');
  }
  sendMessage({
    setConfig: {
      theme: getGiscusTheme(),
    },
  });
}

document.addEventListener('DOMContentLoaded', function () {
  const giscusAttributes = {
    "src": "https://giscus.app/client.js",
    "data-repo": "{{ .Site.Params.giscus.repo }}",
    "data-repo-id": "{{ .Site.Params.giscus.repoID }}",
    "data-category-id": "{{ .Site.Params.giscus.categoryID }}",
    "data-mapping": "{{ default "pathname" .Site.Params.giscus.mapping }}",
    "data-strict": "{{ default "1" .Site.Params.giscus.strict }}",
    "data-reactions-enabled": "{{ default "1" .Site.Params.giscus.reactionsEnabled }}",
    "data-emit-metadata": "{{ default "0" .Site.Params.giscus.emitMetadata }}",
    "data-input-position": "{{ default "top" .Site.Params.giscus.inputPosition }}",
    "data-theme": getGiscusTheme(),
    "data-lang": "{{ default "en" .Site.Params.giscus.lang }}",
    "data-loading": "{{ default "lazy" .Site.Params.giscus.loading }}",
    "crossorigin": "anonymous",
    "async": "",
  };

  // Dynamically create script tag
  const giscusScript = document.createElement("script");
  Object.entries(giscusAttributes).forEach(([key, value]) => giscusScript.setAttribute(key, value));
  document.body.appendChild(giscusScript);

  // Update giscus theme when theme switcher is clicked
  const toggle = document.querySelector('.theme-toggle');
  if (toggle) {
    toggle.addEventListener('click', setGiscusTheme);
  }
});
