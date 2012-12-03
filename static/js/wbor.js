var SEARCH_DJ = "djcomplete"
var SEARCH_SHOW = "showcomplete"

function ajaxSearch(ajaxurl, query, callback) {
    return $.getJSON('/ajax/' + ajaxurl,
                     {'query': query},
                     callback);
}
