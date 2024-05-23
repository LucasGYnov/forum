var sidenav = document.getElementById("mySidenav");
var openBtn = document.getElementById("openBtn");
var closeBtn = document.getElementById("closeBtn");

openBtn.onclick = openNav;
closeBtn.onclick = closeNav;

function openNav() {
    sidenav.classList.add("active");
    openBtn.style.display = "none"; // Masque le bouton burger lorsque le menu est ouvert
}

function closeNav() {
    sidenav.classList.remove("active");
    openBtn.style.display = "block"; // Affiche à nouveau le bouton burger lorsque le menu est fermé
}
