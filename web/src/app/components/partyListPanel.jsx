/*
Copyright 2015 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import React from 'react';

const closeTextStyle = {
  lineHeight: '0px',
  margin: '0px',  
  fontSize: '14px'
}

const PartyListPanel = ({onClose, children}) => {      
  return (
    <div className="grv-terminal-participans">
      <ul className="nav">
        <li title="Close">
          <button onClick={onClose} className="btn btn-danger btn-circle" type="button">
            <div style={closeTextStyle} >&#10005;</div>
          </button>
        </li>
      </ul>
      { children ? <hr className="grv-divider" /> : null }
      { children }      
    </div>
  )
};

export default PartyListPanel;