import shutil
import os
import re

# Solicitar la ubicación de origen del archivo markdown
origen_md = r"D:\Mi unidad\WhiteHatVault\write-Up.md"

# Solicitar la ubicación de origen de las imágenes
origen_imagenes = r"D:\Mi unidad\WhiteHatVault\ANEXOS\Multimedia\Images"

# Solicitar al usuario que seleccione una opción
web = int(input(f"Seleccione Web:\n\t1. HackMyVM\n\t2. Vulnhub\nElige un número: "))

# Definir rutas de destino según la selección del usuario
if web == 1:
    destino_md = r"D:\Mi unidad\Write-UpS\lyonspeed.github.io\collections\_hackmyvm"
    destino_imagenes = r"D:\Mi unidad\Write-UpS\lyonspeed.github.io\assets\images\hackmyvm"
elif web == 2:
    destino_md = r"D:\Mi unidad\Write-UpS\lyonspeed.github.io\collections\_vulnhub"
    destino_imagenes = r"D:\Mi unidad\Write-UpS\lyonspeed.github.io\assets\images\vulnhub"

# Verificar si el archivo markdown de origen existe
if os.path.exists(origen_md):
    try:
        # Copiar el archivo markdown al destino
        shutil.copy(origen_md, destino_md)
        print(f"El archivo markdown se ha copiado exitosamente a {destino_md}")
    except Exception as e:
        print(f"Ocurrió un error al copiar el archivo markdown: {e}")
else:
    print("El archivo markdown de origen no existe. Verifica la ruta ingresada.")

# Verificar si la carpeta de imágenes de origen existe
if os.path.exists(origen_imagenes):
    try:
        # Crear el directorio de destino para las imágenes si no existe
        if not os.path.exists(destino_imagenes):
            os.makedirs(destino_imagenes)
            print(f"Se creó el directorio de destino para las imágenes: {destino_imagenes}")

        # Copiar y renombrar todas las imágenes de la carpeta de origen al destino
        for imagen in os.listdir(origen_imagenes):
            ruta_imagen_origen = os.path.join(origen_imagenes, imagen)
            if os.path.isfile(ruta_imagen_origen):  # Asegurarse de que sea un archivo
                # Renombrar la imagen (reemplazar espacios por guiones bajos)
                nuevo_nombre = imagen.replace(" ", "_")
                ruta_imagen_destino = os.path.join(destino_imagenes, nuevo_nombre)

                # Copiar la imagen al destino con el nuevo nombre
                shutil.copy(ruta_imagen_origen, ruta_imagen_destino)
                print(f"Imagen {imagen} copiada y renombrada a {nuevo_nombre} en {destino_imagenes}")

    except Exception as e:
        print(f"Ocurrió un error al copiar o renombrar las imágenes: {e}")
else:
    print("La carpeta de imágenes de origen no existe. Verifica la ruta ingresada.")

# Función para reemplazar rutas de imágenes en el archivo markdown
def replace_image_paths(md_file):
    with open(md_file, 'r', encoding='utf-8') as file:
        lines = file.readlines()
    
    pattern = re.compile(r'!\[\[(.*?)\]\]')
    
    with open(md_file, 'w', encoding='utf-8') as file:
        for line in lines:
            new_line = pattern.sub(lambda m: f'![](/assets/images/{m.group(1).replace(" ", "_")})', line)
            file.write(new_line)

# Función para agregar el bloque YAML al archivo markdown con una línea en blanco de separación
def add_yaml_front_matter(md_file):
    # Obtener el nombre del archivo sin la extensión
    file_name = os.path.splitext(os.path.basename(md_file))[0]
    
    # Crear el bloque YAML
    yaml_block = f"---\ntitle: {file_name}\nlayout: default\n---\n\n"  # Línea en blanco añadida después del bloque YAML
    
    # Leer el contenido actual del archivo
    with open(md_file, 'r', encoding='utf-8') as file:
        content = file.read()
    
    # Escribir el bloque YAML seguido del contenido original
    with open(md_file, 'w', encoding='utf-8') as file:
        file.write(yaml_block + content)

# Aplicar la función de reemplazo de rutas y agregar el bloque YAML al archivo markdown en destino_md
if os.path.exists(destino_md):
    try:
        # Obtener el nombre del archivo markdown
        md_filename = os.path.basename(origen_md)
        md_file_path = os.path.join(destino_md, md_filename)
        
        # Reemplazar rutas de imágenes en el archivo markdown
        replace_image_paths(md_file_path)
        print(f"Se han reemplazado las rutas de imágenes en {md_filename}")
        
        # Agregar el bloque YAML al archivo markdown
        add_yaml_front_matter(md_file_path)
        print(f"Se ha agregado el bloque YAML al archivo {md_filename}")
    except Exception as e:
        print(f"Ocurrió un error al modificar el archivo markdown: {e}")
else:
    print("El archivo markdown de destino no existe. Verifica la ruta.")