/**
 * File: static/js/report-card.js
 * Final stable version for handling image modals using Bootstrap's standard events.
 * This script is pure client-side JavaScript, free of server-side template syntax.
 */
document.addEventListener('DOMContentLoaded', function () {

  // Get all image modals present on the page
  const allImageModals = document.querySelectorAll('.image-modal');

  allImageModals.forEach(modalElement => {
    
    // Listen for the Bootstrap event that fires just before a modal is shown
    modalElement.addEventListener('show.bs.modal', function (event) {
      
      // 'relatedTarget' is the element the user clicked to open the modal (the .report-image-container div)
      const triggerElement = event.relatedTarget;
      if (!triggerElement) return;

      // Find the small thumbnail image inside the element that was clicked
      const thumbnail = triggerElement.querySelector('.report-image');
      if (!thumbnail) {
        console.error('Thumbnail image to load was not found.');
        return;
      }

      // Find the large image tag and the loading spinner within this specific modal
      const modalImage = modalElement.querySelector('.modal-img');
      const loadingSpinner = modalElement.querySelector('[id^="loading"]');
      
      if (!modalImage || !loadingSpinner) {
        console.error('Modal content elements (image or spinner) not found.');
        return;
      }

      // --- Start Loading Process ---

      // 1. Show the spinner and hide the (still empty) image tag
      loadingSpinner.style.display = 'block';
      modalImage.style.display = 'none';
      
      // 2. Get the high-quality image URL from the thumbnail's src
      const imageUrl = thumbnail.src;

      // 3. Set the src for the large image tag in the modal. This starts the download.
      modalImage.src = imageUrl;

      // 4. Wait for the large image to fully load in the browser's memory
      modalImage.onload = function () {
        // Once loaded, hide the spinner and show the image
        loadingSpinner.style.display = 'none';
        modalImage.style.display = 'block';
      };
      
      // 5. If there's an error loading the large image, show an error message
      modalImage.onerror = function () {
        loadingSpinner.innerHTML = '<p class="text-danger">خطا در بارگذاری تصویر</p>';
        modalImage.style.display = 'none';
      };
    });

    // Listen for the event when the modal is fully hidden to clean it up for the next use
    modalElement.addEventListener('hidden.bs.modal', function () {
       const modalImage = modalElement.querySelector('.modal-img');
       const loadingSpinner = modalElement.querySelector('[id^="loading"]');
       
       // Reset modal to its initial state
       if (modalImage) {
           modalImage.src = ''; // Clear the src to free up memory
       }
       if (loadingSpinner) {
           // Restore the spinner in case an error message was shown
           loadingSpinner.innerHTML = '<div class="spinner-border text-primary" role="status"><span class="visually-hidden">در حال بارگذاری...</span></div>';
       }
    });
  });
});