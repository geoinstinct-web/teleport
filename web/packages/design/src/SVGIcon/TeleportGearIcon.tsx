/**
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import React from 'react';

import { useTheme } from 'styled-components';

import { SVGIcon } from './SVGIcon';

import type { SVGIconProps } from './common';

export function TeleportGearIcon({ size = 16 }: Omit<SVGIconProps, 'fill'>) {
  const theme = useTheme();
  let fill = theme.colors.brand;

  // All other themes will default to white.
  if (theme.type !== 'light') {
    fill = 'white';
  }

  return (
    <SVGIcon size={size} viewBox="0 0 96 98">
      <g id="logos" transform="translate(-478.000000, -46.000000)" fill={fill}>
        <path d="M516.40312,46.9344801 C522.737143,45.6885066 529.265173,45.6885066 535.599196,46.9344801 C536.43814,47.0287134 537.135512,47.7459334 537.282327,48.5155052 L537.282327,48.5155052 L539.704776,60.7553621 C543.364667,62.1479206 546.783362,64.0587623 549.798316,66.4512407 L549.798316,66.4512407 L562.020674,62.3363872 C562.812427,62.0013355 563.651371,62.2421539 564.243875,62.9122573 C568.449079,67.550629 571.862531,73.1522744 573.844535,79.0366196 C574.190599,79.8009562 573.944159,80.7066428 573.252031,81.1882796 L573.252031,81.1882796 L563.551746,89.3185181 C563.89781,91.1351265 563.997435,93.0983199 563.997435,95.0091616 C563.997435,96.9304736 563.89781,98.8884318 563.551746,100.70504 L563.551746,100.70504 L573.252031,108.840514 C573.944159,109.316916 574.190599,110.227837 573.844535,110.992174 C571.867774,116.876519 568.454323,122.472929 564.249118,127.111301 C563.651371,127.781404 562.812427,128.022223 562.020674,127.687171 L562.020674,127.687171 L549.798316,123.572318 C546.783362,125.964796 543.369911,127.880873 539.71002,129.262961 L539.71002,129.262961 L537.282327,141.513288 C537.135512,142.28286 536.43814,142.994845 535.599196,143.094313 C532.432185,143.664948 529.265173,144 526.00378,144 C522.737143,144 519.570132,143.664948 516.40312,143.094313 C515.564176,142.994845 514.866804,142.28286 514.719989,141.513288 L514.719989,141.513288 L512.29754,129.262961 C508.637649,127.880873 505.119329,125.964796 502.204,123.572318 L502.204,123.572318 L489.981642,127.687171 C489.189889,128.022223 488.350945,127.781404 487.753198,127.111301 C483.547994,122.472929 480.134542,116.876519 478.157781,110.992174 C477.811717,110.227837 478.058157,109.316916 478.750285,108.840514 L478.750285,108.840514 L488.445326,100.70504 C488.099262,98.8884318 487.999638,96.9304736 487.999638,95.0091616 C487.999638,93.0983199 488.099262,91.1351265 488.445326,89.3185181 L488.445326,89.3185181 L478.750285,81.1882796 C478.058157,80.7066428 477.806474,79.8009562 478.157781,79.0366196 C480.134542,73.1522744 483.547994,67.550629 487.753198,62.9122573 C488.350945,62.2421539 489.189889,62.0065707 489.981642,62.3363872 L489.981642,62.3363872 L502.204,66.4512407 C505.119329,64.0587623 508.632405,62.1479206 512.29754,60.7553621 L512.29754,60.7553621 L514.719989,48.5155052 C514.866804,47.7459334 515.564176,47.0287134 516.40312,46.9344801 Z M525.997379,66.3259259 C509.88575,66.3259259 496.830769,79.1656021 496.830769,95 C496.830769,110.834398 509.88575,123.674074 525.997379,123.674074 C542.109007,123.674074 555.169231,110.834398 555.169231,95 C555.169231,79.1656021 542.109007,66.3259259 525.997379,66.3259259 Z M544.461538,82.4777778 L544.461538,91.0180828 L530.395462,91.0177778 L530.395604,111.514815 L521.604396,111.514815 L521.603462,91.0177778 L507.538462,91.0180828 L507.538462,82.4777778 L544.461538,82.4777778 Z"></path>
      </g>
    </SVGIcon>
  );
}
