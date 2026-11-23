from app.repository_analysis import MAX_ROUTE_RECORDS, analyse_repository


def write_file(root, name, content):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def test_extracts_python_route_decorators_with_methods(tmp_path):
    write_file(
        tmp_path,
        "service/routes.py",
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.get('/api/users')\n"
        "async def list_users(): pass\n"
        "@app.route('/login', methods=['POST', 'GET'])\n"
        "def login(): pass\n"
        "@app.get(prefix + '/dynamic')\n"
        "def dynamic(): pass\n",
    )

    report = analyse_repository(tmp_path).to_dict()
    routes = {
        (item["method"], item["path"], item["source_path"])
        for item in report["route_inventory"]
    }

    assert ("GET", "/api/users", "service/routes.py") in routes
    assert ("POST", "/login", "service/routes.py") in routes
    assert ("GET", "/login", "service/routes.py") in routes
    assert not any("dynamic" in path for _, path, _ in routes)
    assert report["route_count"] == len(report["route_inventory"])
    assert report["route_inventory_truncated"] is False


def test_extracts_javascript_routes_but_ignores_comments_and_strings(tmp_path):
    write_file(
        tmp_path,
        "server/routes.ts",
        "const app = express();\n"
        "app.get('/api/items', handler);\n"
        "router.post('/api/items/:itemId', handler);\n"
        "// app.get('/commented-line', handler);\n"
        "/* router.delete('/commented-block', handler); */\n"
        """const help = \"example app.get('/inside-string', handler)\";\\n""",
    )

    routes = analyse_repository(tmp_path).to_dict()["route_inventory"]
    paths = {(item["method"], item["path"]) for item in routes}

    assert ("GET", "/api/items") in paths
    assert ("POST", "/api/items/:itemId") in paths
    assert not any("commented" in path or "inside-string" in path for _, path in paths)
    assert all(item["source_path"] == "server/routes.ts" for item in routes)


def test_extracts_go_spring_php_and_ruby_route_clues(tmp_path):
    write_file(
        tmp_path,
        "server.go",
        'http.HandleFunc("/api/go", handler)\n'
        'mux.Handle("/files/", handler)\n',
    )
    write_file(
        tmp_path,
        "Controller.java",
        '@GetMapping("/api/java")\n'
        '@RequestMapping(path="/legacy")\n',
    )
    write_file(
        tmp_path,
        "routes.php",
        "Route::post('/api/php', function () {});\n",
    )
    write_file(
        tmp_path,
        "routes.rb",
        "get '/api/ruby', to: 'health#show'\n",
    )

    routes = analyse_repository(tmp_path).to_dict()["route_inventory"]
    values = {
        (item["method"], item["path"], item["source_path"])
        for item in routes
    }

    assert ("ANY", "/api/go", "server.go") in values
    assert ("ANY", "/files/", "server.go") in values
    assert ("GET", "/api/java", "Controller.java") in values
    assert ("ANY", "/legacy", "Controller.java") in values
    assert ("POST", "/api/php", "routes.php") in values
    assert ("GET", "/api/ruby", "routes.rb") in values


def test_route_inventory_budget_is_explicit(tmp_path):
    routes = "".join(
        f'app.get("/api/route-{index}", handler)\n'
        for index in range(MAX_ROUTE_RECORDS + 1)
    )
    write_file(tmp_path, "routes.js", routes)

    report = analyse_repository(tmp_path).to_dict()

    assert report["route_count"] == MAX_ROUTE_RECORDS
    assert report["route_inventory_truncated"] is True
    assert report["truncated"] is True
