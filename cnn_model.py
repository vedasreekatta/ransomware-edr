def build_cnn(input_shape=(256, 256, 1), number_of_classes=2):
    """
    CNN architecture placeholder.
    We will implement and train this after selecting and preparing the dataset.
    """
    try:
        from tensorflow import keras
        from tensorflow.keras import layers
    except ImportError as exc:
        raise RuntimeError(
            "TensorFlow is not installed. Install a compatible TensorFlow version "
            "when we reach the model-training phase."
        ) from exc

    model = keras.Sequential([
        layers.Input(shape=input_shape),
        layers.Rescaling(1.0 / 255),
        layers.Conv2D(32, 3, activation="relu"),
        layers.MaxPooling2D(),
        layers.Conv2D(64, 3, activation="relu"),
        layers.MaxPooling2D(),
        layers.Conv2D(128, 3, activation="relu"),
        layers.GlobalAveragePooling2D(),
        layers.Dropout(0.3),
        layers.Dense(number_of_classes, activation="softmax"),
    ])
    model.compile(
        optimizer="adam",
        loss="categorical_crossentropy",
        metrics=["accuracy"],
    )
    return model
