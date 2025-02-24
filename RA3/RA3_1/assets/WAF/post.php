<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Formulario Seguro</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <style>
        body {
            background-color: #f8f9fa;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .container {
            max-width: 500px;
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }
    </style>
</head>
<body>

<div class="container">
    <h2 class="text-center mb-4">Formulario Seguro</h2>
    
    <?php
    if ($_SERVER["REQUEST_METHOD"] == "POST") {
        $data = $_POST["data"];
        echo "<div class='alert alert-success'>Entrada recibida: <strong>$data</strong></div>";
    }
    ?>

    <form method="post" action="post.php">
        <div class="mb-3">
            <label for="data" class="form-label">Introduce tu texto</label>
            <input type="text" class="form-control" id="data" name="data" required>
        </div>
        <button type="submit" class="btn btn-primary w-100">Enviar</button>
    </form>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
