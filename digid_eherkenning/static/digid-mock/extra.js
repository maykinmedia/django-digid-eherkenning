(function () {
    "use strict";

    /*
    low-tech vanilla.js replacement code for DigiD's interactive functionality
    */

    var forEach = function (iterable, fn) {
        Array.prototype.forEach.call(iterable, fn);
    };
    var showBlock = function (elem) {
        elem.style.display = 'block';
    };
    var hideBlock = function (elem) {
        elem.style.display = 'none';
    };

    var documentReady = function (callback) {
        if (document.readyState === "complete" || document.readyState === "interactive") {
            setTimeout(callback, 1);
        } else {
            document.addEventListener("DOMContentLoaded", callback);
        }
    };

    var blockPlaceholderLinks = function () {
        var links = document.querySelectorAll('.digidmock-anchor-placeholder');
        forEach(links, function (link) {
            link.addEventListener('click', function (event) {
                event.preventDefault();
                showMessageNear(link, 'Deze functionaliteit werkt niet in de mockup');
            });
        });

    };

    var showMessageNear = function (element, message) {
        // lets do an alert() for now
        alert(message);
    };

    var isEmpty = function (elem) {
        var value = elem.value;
        if (value === undefined) {
            return true;
        }
        value = value.replace(/^\s+|\s+$/g, '');
        return value.length === 0;
    };

    var setupEmptyInputErrors = function () {
        var form = document.querySelector('form#new_authentication');
        if (!form) {
            return;
        }

        var username_input = form.querySelector('#authentication_username');
        var username_empty = form.querySelector('#authentication_username__empty');
        var password_input = form.querySelector('#authentication_password');
        var password_empty = form.querySelector('#authentication_password__empty');

        var username_clear = function () {
            hideBlock(username_empty);
        };
        var password_clear = function () {
            hideBlock(password_empty);
        };

        username_input.addEventListener('focus', username_clear);
        password_input.addEventListener('focus', password_clear);

        form.addEventListener('submit', function (event) {
            var valid = true;
            if (isEmpty(username_input)) {
                valid = false;
                username_input.value = '';
                showBlock(username_empty);
            } else {
                hideBlock(username_empty);
            }

            if (isEmpty(password_input)) {
                valid = false;
                showBlock(password_empty);
            } else {
                hideBlock(password_empty);
            }

            if (!valid) {
                event.preventDefault();
            }
        });
    };

    documentReady(function () {
        blockPlaceholderLinks();
        setupEmptyInputErrors();
    });
}());
