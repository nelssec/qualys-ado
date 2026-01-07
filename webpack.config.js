const path = require("path");
const HtmlWebpackPlugin = require("html-webpack-plugin");
const CopyWebpackPlugin = require("copy-webpack-plugin");

module.exports = {
    entry: {
        "scan-results-tab": "./src/ui/scan-results-tab/scan-results-tab.ts"
    },
    output: {
        filename: "[name]/[name].js",
        path: path.resolve(__dirname, "dist/ui"),
        clean: true
    },
    resolve: {
        extensions: [".ts", ".tsx", ".js"]
    },
    module: {
        rules: [
            {
                test: /\.tsx?$/,
                use: "ts-loader",
                exclude: /node_modules/
            },
            {
                test: /\.css$/,
                use: ["style-loader", "css-loader"]
            }
        ]
    },
    plugins: [
        new HtmlWebpackPlugin({
            template: "./src/ui/scan-results-tab/scan-results-tab.html",
            filename: "scan-results-tab/scan-results-tab.html",
            chunks: ["scan-results-tab"]
        })
    ],
    devtool: "source-map",
    mode: "production",
    optimization: {
        minimize: true
    }
};
