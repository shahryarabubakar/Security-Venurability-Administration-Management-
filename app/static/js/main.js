function openModal(id){
  document.getElementById(id).classList.add('active');
  document.getElementById('modalBackdrop').classList.add('active');
  document.body.style.overflow='hidden';
}
function closeModal(id){
  document.getElementById(id).classList.remove('active');
  if(!document.querySelectorAll('.modal.active').length){
    document.getElementById('modalBackdrop').classList.remove('active');
    document.body.style.overflow='';
  }
}
function closeAllModals(){
  document.querySelectorAll('.modal.active').forEach(m=>m.classList.remove('active'));
  document.getElementById('modalBackdrop').classList.remove('active');
  document.body.style.overflow='';
}
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeAllModals()});
