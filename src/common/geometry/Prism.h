//
// Copyright (C) 2013 OpenSim Ltd.
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//

#ifndef __INET_PRISM_H
#define __INET_PRISM_H

#include "Shape.h"
#include "Polygon.h"

namespace inet {
/**
 * This class represents 3 dimensional prism with a polygon base face.
 * The coordinate system origin is at the first point on the base face.
 */
class INET_API Prism : public Shape
{
  protected:
    double height;
    Polygon base;

  public:
    Prism();

    virtual bool isIntersecting(const LineSegment& lineSegment) const;
    virtual double computeIntersectionDistance(const LineSegment& lineSegment) const;
};
} // namespace inet

#endif // ifndef __INET_PRISM_H
