import os
import re

def normalize_html_name(filename):
    # Matches "Name 85ca7d04ce6d48279f89c762ec1d13d2.html" -> "Name"
    match = re.search(r'^(.*?) [a-f0-9]{32}\.html$', filename)
    if match:
        return match.group(1)
    if filename.endswith('.html'):
        return filename[:-5]
    return filename

def compare():
    notas_dir = 'notas'
    notas_md_dir = 'notas-md'
    
    html_files = {} # Key: normalized path, Value: original path
    html_duplicates = {} # Key: normalized path, Value: list of original paths
    md_files = {}
    other_files_html = {}
    other_files_md = {}

    # Walk notas/
    for root, dirs, files in os.walk(notas_dir):
        try:
            rel_path = os.path.relpath(root, notas_dir)
        except AttributeError:
            rel_path = os.path.splitdrive(root)[1][len(os.path.splitdrive(notas_dir)[1]):].lstrip(os.sep)
            
        if rel_path == '.':
            rel_path = ''
            
        for f in files:
            full_path = os.path.join(root, f)
            if f.endswith('.html'):
                norm_name = normalize_html_name(f).strip()
                rel_norm_path = os.path.join(rel_path, norm_name)
                if rel_norm_path in html_files:
                    if rel_norm_path not in html_duplicates:
                        html_duplicates[rel_norm_path] = [html_files[rel_norm_path]]
                    html_duplicates[rel_norm_path].append(full_path)
                else:
                    html_files[rel_norm_path] = full_path
            else:
                other_files_html[os.path.join(rel_path, f)] = full_path

    # Walk notas-md/
    for root, dirs, files in os.walk(notas_md_dir):
        try:
            rel_path = os.path.relpath(root, notas_md_dir)
        except AttributeError:
            rel_path = os.path.splitdrive(root)[1][len(os.path.splitdrive(notas_md_dir)[1]):].lstrip(os.sep)

        if rel_path == '.':
            rel_path = ''
            
        for f in files:
            full_path = os.path.join(root, f)
            if f.endswith('.md'):
                name = f[:-3].strip()
                md_files[os.path.join(rel_path, name)] = full_path
            else:
                other_files_md[os.path.join(rel_path, f)] = full_path

    print("--- Inconsistencias de Archivos (HTML -> MD) ---")
    missing_md = []
    for rel_name in sorted(html_files.keys()):
        if rel_name not in md_files:
            missing_md.append(html_files[rel_name])
    
    if missing_md:
        print(f"Faltan {len(missing_md)} archivos Markdown para los siguientes HTML:")
        for m in missing_md[:20]:
            print(f"  - {m}")
        if len(missing_md) > 20:
            print(f"  ... y {len(missing_md) - 20} más.")
    else:
        print("Todos los archivos HTML tienen su correspondiente Markdown.")

    print("\n--- Archivos Markdown Huérfanos ---")
    orphans = []
    for rel_name in sorted(md_files.keys()):
        if rel_name not in html_files:
            orphans.append(md_files[rel_name])
    
    if orphans:
        print(f"Se encontraron {len(orphans)} archivos Markdown sin origen HTML:")
        for o in orphans[:20]:
            print(f"  - {o}")
        if len(orphans) > 20:
            print(f"  ... y {len(orphans) - 20} más.")
    else:
        print("No hay archivos Markdown huérfanos.")

    print("\n--- Comparación de Recursos (Imágenes, etc.) ---")
    missing_resources = []
    for rel_name in sorted(other_files_html.keys()):
        if rel_name not in other_files_md:
            missing_resources.append(other_files_html[rel_name])
    
    if missing_resources:
        print(f"Faltan {len(missing_resources)} recursos en notas-md:")
        for r in missing_resources[:20]:
            print(f"  - {r}")
        if len(missing_resources) > 20:
            print(f"  ... y {len(missing_resources) - 20} más.")
    else:
        print("Todos los recursos de 'notas/' están presentes en 'notas-md/'.")

    print("\n--- Recursos Huérfanos en notas-md ---")
    orphan_resources = []
    for rel_name in sorted(other_files_md.keys()):
        if rel_name not in other_files_html:
            orphan_resources.append(other_files_md[rel_name])
    
    if orphan_resources:
        print(f"Se encontraron {len(orphan_resources)} recursos en notas-md sin origen en notas:")
        for orp in orphan_resources[:20]:
            print(f"  - {orp}")
        if len(orphan_resources) > 20:
            print(f"  ... y {len(orphan_resources) - 20} más.")
    else:
        print("No hay recursos huérfanos.")

    if html_duplicates:
        print("\n--- Posibles Duplicados HTML (Mismo nombre base, diferente hash) ---")
        for norm_path, orig_paths in html_duplicates.items():
            print(f"  {norm_path}:")
            for p in orig_paths:
                print(f"    - {p}")
    else:
        print("\nNo se encontraron duplicados en archivos HTML.")

if __name__ == "__main__":
    compare()
