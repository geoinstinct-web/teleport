function getSearchTermFromLocation(){for(var e=window.location.search.substring(1).split("&"),r=0;r<e.length;r++){var o=e[r].split("=");if("q"==o[0])return decodeURIComponent(o[1].replace(/\+/g,"%20"))}}function joinUrl(e,r){return"/"===r.substring(0,1)?r:"/"===e.substring(e.length-1)?e+r:e+"/"+r}function formatResult(e,r,o){return'<article><h3><a href="'+joinUrl(base_url,e)+'">'+r+"</a></h3><p>"+o+"</p></article>"}function displayResults(e){for(var r=document.getElementById("mkdocs-search-results");r.firstChild;)r.removeChild(r.firstChild);if(e.length>0)for(var o=0;o<e.length;o++){var s=e[o],t=formatResult(s.location,s.title,s.summary);r.insertAdjacentHTML("beforeend",t)}else r.insertAdjacentHTML("beforeend","<p>No results found</p>")}function doSearch(){var e=document.getElementById("mkdocs-search-query").value;e.length>2?window.Worker?searchWorker.postMessage({query:e}):displayResults(search(e)):displayResults([])}function initSearch(){var e=document.getElementById("mkdocs-search-query");e&&e.addEventListener("keyup",doSearch);var r=getSearchTermFromLocation();r&&(e.value=r,doSearch())}function onWorkerMessage(e){if(e.data.allowSearch)initSearch();else if(e.data.results){displayResults(e.data.results)}}if(window.Worker){var searchWorker=new Worker(joinUrl(base_url,"search/worker.js"));searchWorker.postMessage({init:!0}),searchWorker.onmessage=onWorkerMessage}else console.log("Web Worker API not supported"),$.getScript(joinUrl(base_url,"search/worker.js")).done(function(){console.log("Loaded worker"),init(),window.postMessage=function(e){onWorkerMessage({data:e})}}).fail(function(e,r,o){console.error("Could not load worker.js")});