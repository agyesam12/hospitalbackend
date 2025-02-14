"use strict";

/*============================================ 
======== Table of JS Functions =========
# modal toggle function
# select item from modal
# modal page open close function
# select active button
# Swiper Slider Start
# preloader
# Go To Home Page
# notification Modal Open
# favorite Modal Open
# notification sortby modal
# Search Filter Modal
# Search Filter Modal
# Top Doctor Modal
# Calendar Modal
# my appoinment tab
# FAQ Item Toggle
# Logout Modal Toggle
# Chat box options modal
# attach options modal
# doctor favourite button toggle
# Work experience button active select
# schedule button active select
# time button active select
# rating button active select
# age button active select

============================================*/

document.addEventListener("DOMContentLoaded", function () {
  /*
===============================================================
=> Reusable Functions Start
===============================================================
  */
  // modal toggle function
  function modalToggle(modalName, modalBox, open, close) {
    modalName.addEventListener("click", () => {
      if (modalBox.classList.contains(open)) {
        modalBox.classList.remove(open);
        modalBox.classList.add(close);
        document.removeEventListener("click", closeDropdownOutside);
      } else {
        modalBox.classList.add(open);
        modalBox.classList.remove(close);
        document.addEventListener("click", closeDropdownOutside);
      }

      function closeDropdownOutside(event) {
        const isClickedInsideDropdown = modalBox.contains(event.target);
        const isClickedOnDropdownBtn = modalName.contains(event.target);

        if (!isClickedInsideDropdown && !isClickedOnDropdownBtn) {
          modalBox.classList.add(close);
          modalBox.classList.remove(open);
          document.removeEventListener("click", closeDropdownOutside);
        }
      }
    });
  }

  //select item from modal
  function selectItemFromModal(items, modalBox, slectText) {
    items.forEach((e) =>
      e.addEventListener("click", () => {
        modalBox.classList.remove("modalClose");
        modalBox.classList.add("modalOpen");
        slectText.innerHTML = e.textContent;
      })
    );
  }

  // modal page open close function
  function pageModlaToggle(
    modalOpenButton,
    modalCloseButton,
    modal,
    openStyle,
    closeStyle
  ) {
    modalOpenButton.addEventListener("click", () => {
      modal.classList.remove(closeStyle);
      modal.classList.add(openStyle);
    });

    modalCloseButton.addEventListener("click", () => {
      modal.classList.add(closeStyle);
      modal.classList.remove(openStyle);
    });
  }

  //select active button
  function selectActiveButton(buttons, activeClass) {
    buttons.forEach((item) => {
      item.addEventListener("click", () => {
        buttons.forEach((item) => {
          if (item.classList.contains(activeClass)) {
            item.classList.remove(activeClass);
          }
        });
        if (item.classList.contains(activeClass)) {
          item.classList.remove(activeClass);
        }
        {
          item.classList.add(activeClass);
        }
      });
    });
  }

  /*
===============================================================
=> Reusable Functions End
===============================================================
*/

  // Swiper Slider Start
  let onbordingSlider1 = document.querySelectorAll(
    ".onbording-carousel-slider1"
  );
  onbordingSlider1 &&
    onbordingSlider1.forEach(function (onbordingSlider1) {
      var swiper = new Swiper(onbordingSlider1, {
        direction: "vertical",
        loop: true,
        slidesPerView: 4,
        spaceBetween: 24,
        speed: 6000,
        autoplay: {
          delay: 1,
        },
      });
    });

  let onbordingSlider2 = document.querySelectorAll(
    ".onbording-carousel-slider2"
  );
  onbordingSlider2 &&
    onbordingSlider2.forEach(function (onbordingSlider2) {
      var swiper = new Swiper(onbordingSlider2, {
        direction: "vertical",
        loop: true,
        slidesPerView: 4,
        spaceBetween: 24,
        speed: 6000,
        autoplay: {
          delay: 100,
          reverseDirection: true,
        },
      });
    });

  let bottomStepsSlider = document.querySelectorAll(".bottom-steps-slider");
  bottomStepsSlider &&
    bottomStepsSlider.forEach(function (bottomStepsSlider) {
      var swiper = new Swiper(bottomStepsSlider, {
        loop: true,
        slidesPerView: 1,
        slidesToShow: 1,
        paginationClickable: true,
        spaceBetween: 12,
        pagination: {
          el: ".swiper-pagination",
          clickable: true,
        },
        navigation: {
          nextEl: bottomStepsSlider.querySelector(".ara-next"),
          prevEl: bottomStepsSlider.querySelector(".ara-prev"),
        },
      });
    });

  let doctorAppointmentSlider = document.querySelectorAll(
    ".doctor-appointment-slider"
  );
  doctorAppointmentSlider &&
    doctorAppointmentSlider.forEach(function (doctorAppointmentSlider) {
      var swiper = new Swiper(doctorAppointmentSlider, {
        loop: true,
        slidesPerView: 1.1,

        slidesToShow: 1,
        paginationClickable: true,
        spaceBetween: 12,
        centeredSlides: true,
        pagination: {
          el: ".swiper-pagination",
          clickable: true,
        },
      });
    });

  let doctorSpecialitySlider = document.querySelectorAll(
    ".doctor-speciality-slider"
  );
  doctorSpecialitySlider &&
    doctorSpecialitySlider.forEach(function (doctorSpecialitySlider) {
      var swiper = new Swiper(doctorSpecialitySlider, {
        loop: true,
        slidesPerView: 1.8,

        slidesToShow: 1,
        paginationClickable: true,
        spaceBetween: 12,
      });
    });

  // Swiper Slider End

  //preloader
  const preloader = document.querySelector(".preloader");

  setTimeout(function () {
    preloader && preloader.classList.add("active");
  }, 0);

  setTimeout(() => {
    preloader && preloader.classList.add("hidden");
    preloader && preloader.classList.remove("active");
  }, 500);

  // Go To Home Page
  const goToHomeButton = document.querySelector("#goToHomePage");
const sliderSelect = document.querySelector(".bottom-steps-slider");

let count = 1;
goToHomeButton &&
  goToHomeButton.addEventListener("click", () => {
    const totalSlider = sliderSelect.querySelectorAll(".swiper-slide");
    count++;
    if (count > totalSlider.length) {
      const homeUrl = goToHomeButton.dataset.homeUrl; // Get the URL from data attribute
      window.location.href = homeUrl;
    }
  });

  // notification Modal Open
  const notificationModalOpenButton = document.querySelector(
    "#notificationModalOpenButton"
  );
  const notificationModalCloseButton = document.querySelector(
    "#notificationModalCloseButton"
  );
  const notificationModal = document.querySelector(".notificationModal");

  notificationModal &&
    pageModlaToggle(
      notificationModalOpenButton,
      notificationModalCloseButton,
      notificationModal,
      "fullPageModalOpen",
      "fullPageModalClose"
    );

  // favorite Modal Open
  const favoriteModalOpenButton = document.querySelector(
    "#favoriteModalOpenButton"
  );
  const favoriteModalCloseButton = document.querySelector(
    "#favoriteModalCloseButton"
  );
  const favoriteModal = document.querySelector(".favouriteModal");

  favoriteModal &&
    pageModlaToggle(
      favoriteModalOpenButton,
      favoriteModalCloseButton,
      favoriteModal,
      "fullPageModalOpen",
      "fullPageModalClose"
    );

  // notification sortby modal
  const notificationSortBy = document.querySelector("#notificationSortBy");
  const notificationSortByModal = document.querySelector(
    "#notificationSortByModal"
  );

  const sortByText = document.querySelector(".sortByText");
  const sortByItem = document.querySelectorAll(".sortbyItem");

  notificationSortBy &&
    modalToggle(
      notificationSortBy,
      notificationSortByModal,
      "modalOpen",
      "modalClose"
    );

  sortByText &&
    selectItemFromModal(sortByItem, notificationSortByModal, sortByText);

  // Search Filter Modal
  const filterModalOpenButton = document.querySelector(
    "#filterModalOpenButton"
  );
  const filterModalCloseButton = document.querySelector(
    "#filterModalCloseButton"
  );
  const filterModal = document.querySelector(".filterModal");

  filterModal &&
    pageModlaToggle(
      filterModalOpenButton,
      filterModalCloseButton,
      filterModal,
      "fullPageModalOpen",
      "fullPageModalClose"
    );

  // Search Filter Modal
  const specialityModalOpenButton = document.querySelector(
    "#specialityModalOpenButton"
  );
  const specialityModalCloseButton = document.querySelector(
    "#specialityModalCloseButton"
  );
  const specialityModal = document.querySelector(".specialityModal");

  specialityModal &&
    pageModlaToggle(
      specialityModalOpenButton,
      specialityModalCloseButton,
      specialityModal,
      "fullPageModalOpen",
      "fullPageModalClose"
    );

  // Top Doctor Modal
  const topDoctorModalOpenButton = document.querySelector(
    "#topDoctorModalOpenButton"
  );
  const topDoctorModalCloseButton = document.querySelector(
    "#topDoctorModalCloseButton"
  );
  const topDoctorModal = document.querySelector(".topDoctorModal");

  topDoctorModal &&
    pageModlaToggle(
      topDoctorModalOpenButton,
      topDoctorModalCloseButton,
      topDoctorModal,
      "fullPageModalOpen",
      "fullPageModalClose"
    );

  // Calendar Modal
  const calendarModalOpenButton = document.querySelector(
    "#calendarModalOpenButton"
  );
  const calendarModalCloseButton = document.querySelector(
    "#calendarModalCloseButton"
  );
  const calendarModal = document.querySelector(".calendarModal");

  calendarModal &&
    pageModlaToggle(
      calendarModalOpenButton,
      calendarModalCloseButton,
      calendarModal,
      "fullPageModalOpen",
      "fullPageModalClose"
    );

  // my appoinment tab
  document.addEventListener("DOMContentLoaded", () => {
    // Set "Upcoming" as the default active tab
    const upcoming_data = document.querySelector("#upcoming_data");
    const upcoming = document.querySelector("#upcoming");
  
    if (upcoming_data) {
      upcoming_data.removeAttribute("hidden"); // Make the default tab visible
    }
  
    if (upcoming) {
      upcoming.classList.add("active");
    }
  });
  // my appoinment tab
document.addEventListener("DOMContentLoaded", () => {
  // Set "Upcoming" as the default active tab
  const upcoming_data = document.querySelector("#upcoming_data");
  const upcoming = document.querySelector("#upcoming");

  if (upcoming_data) {
    upcoming_data.hidden = false; // Make the default tab visible
  }

  if (upcoming) {
    upcoming.classList.add("active");
  }
});

// Tab switching logic
const tabButtons = document.querySelectorAll(".tabButton");

tabButtons.forEach((tab) => {
  tab.addEventListener("click", () => {
    // Hide all tabs
    const allTabs = document.querySelectorAll(".tab-content");
    allTabs.forEach((tabContent) => {
      tabContent.hidden = true; // Hide each tab content
    });

    // Remove active state from all tab buttons
    const activeTabButton = document.querySelector(".tabButton.active");
    if (activeTabButton) {
      activeTabButton.classList.remove("active");
    }

    // Show the clicked tab content
    const targetTab = document.querySelector(`#${tab.id}_data`);
    if (targetTab) {
      targetTab.hidden = false; // Make the clicked tab content visible
    }

    // Add active state to the clicked tab button
    tab.classList.add("active");
  });
});
    
  // FAQ Item Toggle
  let accordion = document.querySelectorAll(".faq-accordion");

  accordion.forEach((item, index) => {
    accordion[index].addEventListener("click", function () {
      let faqAnswer = this.nextElementSibling;
      let parent = accordion[index].parentElement;

      // Close all other accordions
      accordion.forEach((otherAccordion, otherIndex) => {
        if (otherIndex !== index) {
          let otherFaqAnswer = otherAccordion.nextElementSibling;
          otherFaqAnswer.style.height = null;
          otherAccordion.querySelector("i").classList.remove("p1-color");
          otherAccordion.parentElement.classList.remove("active");
        }
      });

      // Toggle open/close for the clicked accordion
      if (faqAnswer.style.height) {
        faqAnswer.style.height = null;
      } else {
        faqAnswer.style.height = faqAnswer.scrollHeight + "px";
      }

      accordion[index].parentElement.classList.add("active");

      // Toggle classes for the clicked accordion
      accordion[index].querySelector("i").classList.toggle("ph-caret-down");
      accordion[index].querySelector("i").classList.toggle("ph-caret-up");
      accordion[index].querySelector("i").classList.add("p1-color");
    });
  });

  // Logout Modal Toggle
  const logoutModalButton = document.querySelectorAll(".logoutModalButton");
  const cancelButton = document.querySelector("#cancelButton");
  const logoutModalBg = document.querySelector("#logoutModalBg");
  const logoutModal = document.querySelector("#logoutModal");

  logoutModalButton &&
    logoutModalButton.forEach((item) => {
      item.addEventListener("click", () => {
        logoutModalBg.classList.add("active");
        logoutModal.classList.remove("logoutModalClose");
        logoutModal.classList.add("logoutModalOpen");
      });
    });

  cancelButton &&
    cancelButton.addEventListener("click", () => {
      logoutModalBg.classList.remove("active");
      logoutModal.classList.remove("logoutModalOpen");
      logoutModal.classList.add("logoutModalClose");
    });

  // Chat box options modal
  const moreButton = document.querySelector("#moreButton");
  const moreButtonModal = document.querySelector(".moreButtonModal");

  moreButton &&
    modalToggle(moreButton, moreButtonModal, "modalOpen", "modalClose");

  // attach options modal
  const attachFileButton = document.querySelector("#attachFileButton");
  const attachFileModal = document.querySelector(".attachFileModal");

  attachFileButton &&
    modalToggle(attachFileButton, attachFileModal, "modalOpen", "modalClose");

  // doctor favourite button toggle
  const doctorFavouriteButton = document.querySelectorAll(".doctorFavourite");

  doctorFavouriteButton &&
    doctorFavouriteButton.forEach((item) => {
      item.addEventListener("click", () => {
        const iconSelect = item.querySelector("i");

        if (item.classList.contains("active")) {
          item.classList.remove("active");

          iconSelect.classList.add("ph");
          iconSelect.classList.remove("ph-fill");
        } else {
          item.classList.add("active");

          iconSelect.classList.remove("ph");
          iconSelect.classList.add("ph-fill");
        }
      });
    });

  // Work experience button active select
  const experienceButton = document.querySelectorAll(".experienceButton");

  experienceButton && selectActiveButton(experienceButton, "active");

  // schedule button active select
  const scheduleButton = document.querySelectorAll(".scheduleButton");

  scheduleButton && selectActiveButton(scheduleButton, "active");

  // time button active select
  const timeButton = document.querySelectorAll(".timeButton");

  timeButton && selectActiveButton(timeButton, "active");

  // rating button active select
  const ratingButton = document.querySelectorAll(".ratingButton");

  ratingButton && selectActiveButton(ratingButton, "active");

  // age button active select
  const ageButton = document.querySelectorAll(".ageButton");

  ageButton && selectActiveButton(ageButton, "active");
});