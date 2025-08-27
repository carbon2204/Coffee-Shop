document.addEventListener('DOMContentLoaded', function() {
    console.log("JavaScript загружен и готов к работе!");
    // Пример интерактивного поведения: при клике на товар выводим уведомление
    document.querySelectorAll('.product').forEach(function(product) {
        product.addEventListener('click', function() {
            const productName = this.querySelector('h3').innerText;
            alert("Вы выбрали: " + productName);
        });
    });
});
