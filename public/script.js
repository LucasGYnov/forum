var sidenav = document.getElementById("mySidenav");
var openBtn = document.getElementById("openBtn");
var closeBtn = document.getElementById("closeBtn");
var addPostBtn = document.getElementById("add-button");
var addPostModal = document.getElementById("add-post-modal");
var closeModal = document.querySelector("#add-post-modal .close");
var filtersBtn = document.getElementById("filters-button");
var filtersModal = document.getElementById("filters-modal");
var closeFiltersModal = document.querySelector("#filters-modal .close");

openBtn.onclick = openNav;
closeBtn.onclick = closeNav;
addPostBtn.onclick = openAdd;
closeModal.onclick = closeAdd;
filtersBtn.onclick = openFilters;
closeFiltersModal.onclick = closeFilters;

function openNav() {
    sidenav.classList.add("active");
    openBtn.style.display = "none";
}

function closeNav() {
    sidenav.classList.remove("active");
    openBtn.style.display = "block";
}

function openAdd() {
    addPostModal.classList.add("show");
}

function closeAdd() {
    addPostModal.classList.remove("show");
}

function openFilters() {
    filtersModal.classList.add("show");
}

function closeFilters() {
    filtersModal.classList.remove("show");
}

window.onclick = function(event) {
    if (event.target == addPostModal) {
        closeAdd();
    }
    if (event.target == filtersModal) {
        closeFilters();
    }
}


const prevButton = document.querySelector('.prev');
const nextButton = document.querySelector('.next');
const carouselContainer = document.querySelector('.carousel-container');

let offset = 0;

prevButton.addEventListener('click', () => {
    offset -= 200;
    if (offset < 0) {
        offset = 0;
    }
    carouselContainer.style.transform = `translateX(-${offset}px)`;
});

nextButton.addEventListener('click', () => {
    const maxOffset = carouselContainer.scrollWidth - carouselContainer.clientWidth;
    offset += 200;
    if (offset > maxOffset) {
        offset = maxOffset;
    }
    carouselContainer.style.transform = `translateX(-${offset}px)`;
});

