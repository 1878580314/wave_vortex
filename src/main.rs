mod analysis;

fn main() {
    println!("Running Security Analysis Suite...");
    println!("=================================");
    
    // 调用分析模块的公共函数
    analysis::run();

    println!("=================================");
    println!("Analysis finished.");
    println!("To run performance benchmarks, use: `cargo bench`");
}