(() => {
  const tools = document.querySelector(".research-tools");
  const cards = [...document.querySelectorAll(".article-card")];

  if (!tools || cards.length === 0) return;

  const categoryFilter = tools.querySelector("#category-filter");
  const search = tools.querySelector("#article-search");
  const count = document.querySelector("#research-count");
  const emptyResults = document.querySelector(".empty-results");
  const pagination = document.querySelector(".pagination");
  const paginationPages = pagination.querySelector(".pagination-pages");
  const previousButton = pagination.querySelector(".pagination-previous");
  const nextButton = pagination.querySelector(".pagination-next");
  const pageSize = 10;
  let currentPage = 1;

  const getPageNumbers = (pageCount) => {
    const pages = new Set([1, pageCount]);

    for (let page = currentPage - 2; page <= currentPage + 2; page += 1) {
      if (page > 1 && page < pageCount) pages.add(page);
    }

    return [...pages].sort((left, right) => left - right);
  };

  const renderPagination = (pageCount) => {
    paginationPages.replaceChildren();
    pagination.hidden = pageCount <= 1;
    previousButton.disabled = currentPage === 1;
    nextButton.disabled = currentPage === pageCount;

    let previousPage = 0;
    getPageNumbers(pageCount).forEach((page) => {
      if (page - previousPage > 1) {
        const ellipsis = document.createElement("span");
        ellipsis.className = "pagination-ellipsis";
        ellipsis.textContent = "…";
        ellipsis.setAttribute("aria-hidden", "true");
        paginationPages.append(ellipsis);
      }

      const button = document.createElement("button");
      button.type = "button";
      button.textContent = page;
      button.setAttribute("aria-label", `Page ${page}`);

      if (page === currentPage) {
        button.className = "is-current";
        button.setAttribute("aria-current", "page");
      }

      button.addEventListener("click", () => {
        currentPage = page;
        updateResults();
      });
      paginationPages.append(button);
      previousPage = page;
    });
  };

  const updateResults = (resetPage = false) => {
    if (resetPage) currentPage = 1;

    const activeCategory = categoryFilter.value;
    const query = search.value.trim().toLowerCase();
    const matchingCards = cards.filter((card) => {
      const categoryMatches = activeCategory === "all" || card.dataset.category === activeCategory;
      const searchMatches = card.dataset.search.includes(query);
      return categoryMatches && searchMatches;
    });
    const pageCount = Math.max(1, Math.ceil(matchingCards.length / pageSize));
    currentPage = Math.min(currentPage, pageCount);
    const pageStart = (currentPage - 1) * pageSize;
    const visibleCards = new Set(matchingCards.slice(pageStart, pageStart + pageSize));

    cards.forEach((card) => {
      card.hidden = !visibleCards.has(card);
    });

    count.textContent = `${matchingCards.length} ${matchingCards.length === 1 ? "report" : "reports"}`;
    emptyResults.hidden = matchingCards.length !== 0;
    renderPagination(pageCount);
  };

  previousButton.addEventListener("click", () => {
    currentPage -= 1;
    updateResults();
  });
  nextButton.addEventListener("click", () => {
    currentPage += 1;
    updateResults();
  });
  categoryFilter.addEventListener("change", () => updateResults(true));
  search.addEventListener("input", () => updateResults(true));
  tools.hidden = false;
  updateResults();
})();