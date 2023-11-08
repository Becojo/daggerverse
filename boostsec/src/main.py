import dagger
from dagger.mod import function


@function
def cli(report: str) -> dagger.Container:
    return (
        dagger.container()
        .from_("alpine/curl")
        .with_exec(["sh", "-ce", "curl https://assets.build.boostsecurity.io | sh"])
    )


@function
async def semgrep(path: dagger.Directory, semgrep_rules: str = "auto") -> dagger.File:
    image = "returntocorp/semgrep@sha256:b4637a27abf1e49aeab753fdfd41d917493d8fc7f6da9de2daf109b4d7369fe8"
    converter = "public.ecr.aws/boostsecurityio/boost-scanner-semgrep:366eecf@sha256:7d705102447e03abdad0cac0b756ff46303079200316e2f60b12cdb5b300655c"

    report = (
        dagger.container()
        .from_(image)
        .with_directory("/src", path)
        .with_workdir("/src")
        .with_env("SEMGREP_RULES", semgrep_rules)
        .with_exec(["semgrep", "scan", "--sarif", "--output", "/tmp/report.sarif"])
        .file("/tmp/report.sarif")
    )

    boost_sarif = (
        dagger.container()
        .from_(converter)
        .with_file("/report.sarif", report)
        .with_exec(["process", "/report.sarif"], redirect_stdout="/tmp/boost.sarif")
        .file("/tmp/boost.sarif")
    )

    return boost_sarif
