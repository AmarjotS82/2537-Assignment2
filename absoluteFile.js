global.base_directory = __dirname;
global.absolute_path = function(path) {
	return base_directory + path;
}
global.include = function(fileName) {
	return require(absolute_path('/' + fileName));
}