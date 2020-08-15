use cc;

fn main() {
    cc::Build::new()
            .file("src/windows/c_analysis.c")
            .compile("c_analysis");
}