# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['ids_UI.py'],
<<<<<<< HEAD
    pathex=['src'],
    binaries=[],
    datas=[
        ('models', 'models'),
        ('config.yaml', '.'),
        ('users.db', '.'),
    ],
    hiddenimports=['sklearn.utils._cython_blas', 'sklearn.neighbors.typedefs', 'sklearn.neighbors.quad_tree', 'sklearn.tree._utils'],
=======
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
>>>>>>> main
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
<<<<<<< HEAD
    [],
    exclude_binaries=True,
    name='IDS_System',
=======
    a.binaries,
    a.datas,
    [],
    name='ids_UI',
>>>>>>> main
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
<<<<<<< HEAD
    console=True,
=======
    console=False,
>>>>>>> main
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
<<<<<<< HEAD

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='IDS_System',
)
=======
>>>>>>> main
