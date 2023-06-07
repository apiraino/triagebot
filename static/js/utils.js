const url = "http://127.0.0.1:8000/review-settings";

if (!window.fetch) {
  postData = postDataLikeIts1992
}

function postDataLikeIts1992() {
  const form = new URLSearchParams(new FormData(document.getElementById("review-capacity-form")));
  var http = new XMLHttpRequest();
  var params = '';
  for (var i=0; i<form.length; i++) {
    params = form[i] + '&=' + form[i];
  }
  http.open('POST', url, true);
  http.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
  http.onreadystatechange = function() {
    if (http.readyState == 4 && http.status == 201) {
      console.debug(http.responseText);
      update_view(JSON.parse(http.responseText), "View updated", "success");
    }
  }
  http.send(params);
}


async function update_view(content, msg, result_class) {
  var container = document.getElementById("message");
  container.innerHTML = msg;
  container.classList.add(result_class);

  // populate table
  var my_prefs = document.getElementById("my_prefs");
  var other_prefs = document.getElementById("other_prefs");
  var my_row = '';
  var other_rows = '';
  for (var i=0; i<content.length; i++) {
    const obj = content[i];
    // console.debug(i + ", " + obj.username);
    const pto_start = new Date(obj.pto_date_start).toISOString().split('T')[0];
    const pto_end = new Date(obj.pto_date_end).toISOString().split('T')[0];
    const active = obj.active == true ? "checked=checked" : ''
    const publish = obj.publish_prefs == true ? "checked=checked" : ''

    // first line is assumed to b user's prefs (sorting done by the server)
    // all other lines are the team (always read_only)
    if (i == 0) {
      var disabled = obj.active !== true ? 'disabled' : '';
      my_row = `
<tr>
<td>
  <input id=id name=id type=hidden value=${obj.id}>
  <input id=user_id name=user_id type=hidden value=${obj.user_id}>
  <input id=username name=username type=hidden value=${obj.username}
  <a href="https://github.com/rust-lang/rust/pulls/assigned/${obj.username}">${obj.username}</a>
</td>
<td><label><input id=active name=active type=checkbox ${active} onClick="enableDisableFields(this.checked);"></label></td>
<td>
<input id=enable_max_assigned_prs name=enable_max_assigned_prs type=checkbox checked=checked ${disabled} onClick="enableDisableField(this.checked);">
<input id=max_assigned_prs name=max_assigned_prs type=number value=${obj.max_assigned_prs} ${disabled}></td>
<td>
  <input id=pto_date_start name=pto_date_start type=date value=${pto_start} ${disabled}>&nbsp;
  <input id=pto_date_end name=pto_date_end type=date value=${pto_end} ${disabled}>
</td>
<td><input id=allow_ping_after_days name=allow_ping_after_days type=number value=${obj.allow_ping_after_days} ${disabled}></td>
<td><label><input id=publish_prefs name="publish_prefs" type=checkbox ${publish}></label></td>
</tr>
`;
    } else {
      other_rows += `
<tr>
<td><a href="https://github.com/rust-lang/rust/pulls/assigned/${obj.username}">${obj.username}</a></td>
<td><label><input id=x type=checkbox ${active} disabled></label></td>
<td><input id=x type=number value=${obj.max_assigned_prs} disabled></td>
<td>
  <input id=x type=date value=${pto_start} disabled>&nbsp;
  <input id=x type=date value=${pto_end} disabled>
</td>
<td><input id=x type=number value=${obj.allow_ping_after_days} disabled></td>
<td><label><input id=x type=checkbox ${publish} disabled></label></td>
</tr>
`;
    }
  }
  my_prefs.insertAdjacentHTML('beforeend', my_row);
  other_prefs.insertAdjacentHTML('beforeend', other_rows);
}

async function getData(user) {
  const response = await fetch(url, {
    method: "GET",
    headers: { "Role": user}
  });
  return response.json();
}

async function postData() {
  const form = new URLSearchParams(new FormData(document.getElementById("review-capacity-form")));
  console.debug(form);
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Authorization": "Bearer XXX",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: form,
  });
  update_view(response.json(), "View updated", "success").await;
};

function enableDisableField(is_checked) {
  var elem = document.getElementById('max_assigned_prs');
  if (is_checked === true) {
    elem.removeAttribute('disabled', '');
  } else {
    elem.setAttribute('disabled', 'disabled');
  }
}

function enableDisableFields(is_checked) {
  const form = document.querySelectorAll('form')[0];
  var flds = ['enable_max_assigned_prs', 'max_assigned_prs', 'pto_date_start', 'pto_date_end','allow_ping_after_days'];
  Array.from(form.elements).forEach((input) => {
    const elem = document.getElementById(input.id);
    if (flds.includes(elem.id)) {
      if (is_checked === true) {
        elem.removeAttribute('disabled', '');
      } else {
        elem.setAttribute('disabled', 'disabled');
      }
    }
  });
}

// load initial data
var isAdmin = false;
if (document.location.href.includes('admin') === true) {
  isAdmin = true;
}

var u = document.location.search.split('=')[1];
const user = u !== undefined ? u : 'pnkfelix';

getData(user).then((data) => {
  update_view(data, "View loaded", "success").await;
}).catch(error => {
  update_view({}, "Server is offline", "fail").await;
});
